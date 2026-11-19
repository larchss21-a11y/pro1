package com.nexus.firewall

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.Executors

/** Cliente del servidor Nexus (Hostinger): cuentas, licencia premium, pagos, control remoto e IA. */
object Remote {
    fun api(action: String, body: JSONObject = JSONObject(), timeoutMs: Int = 20000): JSONObject {
        val base = Store.serverUrl
        if (base.isEmpty()) throw Exception("Configura la URL del servidor en Cuenta")
        val sep = if (base.contains("?")) "&" else "?"
        val c = URL("$base${sep}api=$action").openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.connectTimeout = 15000
        c.readTimeout = timeoutMs
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        if (Store.authToken.isNotEmpty()) c.setRequestProperty("X-Nexus-Token", Store.authToken)
        body.put("device_id", Store.deviceId)
        c.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        val code = c.responseCode
        val stream = if (code in 200..299) c.inputStream else (c.errorStream ?: c.inputStream)
        val txt = stream.bufferedReader().use { it.readText() }
        val o = try { JSONObject(txt) } catch (e: Exception) { throw Exception("Respuesta inválida del servidor (HTTP $code)") }
        if (!o.optBoolean("ok", false)) throw Exception(o.optString("error", "Error HTTP $code"))
        return o
    }

    fun refreshLicense(): JSONObject {
        val o = api("me")
        val lic = o.optJSONObject("license") ?: JSONObject()
        lic.put("premium_features", o.optJSONArray("premium_features") ?: JSONArray())
        lic.put("plans", o.optJSONArray("plans") ?: JSONArray())
        lic.put("checked", System.currentTimeMillis())
        Store.saveLicense(lic)
        return o
    }

    fun payUrl(planId: Int): String {
        val base = Store.serverUrl
        val sep = if (base.contains("?")) "&" else "?"
        return "$base${sep}page=pay&plan=$planId&token=" + URLEncoder.encode(Store.authToken, "UTF-8")
    }

    /** Sincroniza estado y ejecuta los comandos que las IA dejaron en el servidor. */
    fun syncOnce() {
        if (Store.authToken.isEmpty() || !Store.allowed(Features.MCP_REMOTE)) return
        val state = Controller.status()
        state.put("ultimos_registros", JSONArray().also { a ->
            Store.recentLogs(40).forEach {
                a.put(JSONObject().put("dominio", it.domain).put("app", it.pkg).put("bloqueado", it.blocked).put("motivo", it.reason))
            }
        })
        val resp = api("device_sync", JSONObject().put("state", state).put("model", Build.MODEL))
        val cmds = resp.optJSONArray("commands") ?: return
        for (i in 0 until cmds.length()) {
            val c = cmds.getJSONObject(i)
            val result = try {
                Controller.execute(c.optString("tool"), c.optJSONObject("args") ?: JSONObject())
            } catch (e: Exception) { JSONObject().put("error", e.message ?: "error") }
            try { api("command_result", JSONObject().put("id", c.optLong("id")).put("result", result)) } catch (_: Exception) { }
        }
    }
}

/** Servidor MCP (JSON-RPC sobre HTTP, transporte "Streamable HTTP") dentro del teléfono. */
class McpServer(private val port: Int, private val lan: Boolean) {
    private var server: ServerSocket? = null
    private val pool = Executors.newFixedThreadPool(4)
    @Volatile private var running = false

    fun start() {
        running = true
        Thread({
            try {
                val s = ServerSocket()
                s.reuseAddress = true
                val bind = if (lan) InetAddress.getByName("0.0.0.0") else InetAddress.getByName("127.0.0.1")
                s.bind(InetSocketAddress(bind, port))
                server = s
                while (running) {
                    val client = try { s.accept() } catch (e: Exception) { if (!running) break else continue }
                    pool.execute { handle(client) }
                }
            } catch (_: Exception) { }
        }, "nexus-mcp").start()
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) { }
        pool.shutdownNow()
    }

    private fun readLine(ins: BufferedInputStream): String {
        val b = ByteArrayOutputStream()
        while (true) {
            val c = ins.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) b.write(c)
            if (b.size() > 16384) break
        }
        return b.toString("UTF-8")
    }

    private fun handle(sock: Socket) {
        sock.use { s ->
            try {
                s.soTimeout = 15000
                val ins = BufferedInputStream(s.getInputStream())
                val out = s.getOutputStream()
                val first = readLine(ins)
                val parts = first.split(" ")
                if (parts.size < 2) return
                val method = parts[0].uppercase()
                val path = parts[1]
                val headers = HashMap<String, String>()
                while (true) {
                    val l = readLine(ins)
                    if (l.isEmpty()) break
                    val i = l.indexOf(':')
                    if (i > 0) headers[l.substring(0, i).trim().lowercase()] = l.substring(i + 1).trim()
                }
                if (method == "OPTIONS") { respond(out, 204, ""); return }
                if (!path.startsWith("/mcp")) { respond(out, 404, "{\"error\":\"usa /mcp\"}"); return }
                // Autenticación por token (cabecera Authorization: Bearer XXX o ?token=XXX)
                val auth = headers["authorization"]?.removePrefix("Bearer ")?.trim()
                    ?: path.substringAfter("token=", "").substringBefore('&')
                val tok = Store.mcpTokens().firstOrNull { it.token == auth }
                if (tok == null) { respond(out, 401, "{\"error\":\"token MCP inválido\"}"); return }
                if (method == "GET") { respond(out, 405, ""); return }
                val len = headers["content-length"]?.toIntOrNull() ?: 0
                if (len <= 0 || len > 2_000_000) { respond(out, 400, "{\"error\":\"cuerpo vacío\"}"); return }
                val body = ByteArray(len)
                var read = 0
                while (read < len) {
                    val r = ins.read(body, read, len - read)
                    if (r < 0) break
                    read += r
                }
                val req = JSONObject(String(body, 0, read, Charsets.UTF_8))
                val res = rpc(req, tok)
                if (res == null) respond(out, 202, "") else respond(out, 200, res.toString())
            } catch (e: Exception) {
                try { respond(s.getOutputStream(), 500, JSONObject().put("error", e.message ?: "error").toString()) } catch (_: Exception) { }
            }
        }
    }

    private fun respond(out: OutputStream, code: Int, body: String) {
        val status = when (code) { 200 -> "OK"; 202 -> "Accepted"; 204 -> "No Content"; 401 -> "Unauthorized"; 404 -> "Not Found"; 405 -> "Method Not Allowed"; 400 -> "Bad Request"; else -> "Error" }
        val bytes = body.toByteArray(Charsets.UTF_8)
        val h = "HTTP/1.1 $code $status\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            "Content-Length: ${bytes.size}\r\n" +
            "Access-Control-Allow-Origin: *\r\n" +
            "Access-Control-Allow-Headers: *\r\n" +
            "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n" +
            "Connection: close\r\n\r\n"
        out.write(h.toByteArray(Charsets.UTF_8))
        out.write(bytes)
        out.flush()
    }

    companion object {
        /** Procesa una petición JSON-RPC MCP. Devuelve null para notificaciones. */
        fun rpc(req: JSONObject, tok: McpToken): JSONObject? {
            val id = req.opt("id")
            val method = req.optString("method")
            if (id == null || method.startsWith("notifications/")) return null
            val res = JSONObject().put("jsonrpc", "2.0").put("id", id)
            when (method) {
                "initialize" -> {
                    val pv = req.optJSONObject("params")?.optString("protocolVersion", "2025-06-18") ?: "2025-06-18"
                    res.put("result", JSONObject()
                        .put("protocolVersion", pv)
                        .put("capabilities", JSONObject().put("tools", JSONObject()))
                        .put("serverInfo", JSONObject().put("name", "nexus-firewall").put("version", BuildConfig.VERSION_NAME))
                        .put("instructions", "Controla el firewall Nexus del teléfono Android. Token: ${tok.name} (${tok.scope})."))
                }
                "ping" -> res.put("result", JSONObject())
                "tools/list" -> {
                    val a = JSONArray()
                    Controller.TOOLS.filter { tok.scope == "full" || !it.optBoolean("write") }.forEach {
                        a.put(JSONObject().put("name", it.getString("name")).put("description", it.getString("description"))
                            .put("inputSchema", it.getJSONObject("inputSchema")))
                    }
                    res.put("result", JSONObject().put("tools", a))
                }
                "tools/call" -> {
                    val p = req.optJSONObject("params") ?: JSONObject()
                    val name = p.optString("name")
                    val args = p.optJSONObject("arguments") ?: JSONObject()
                    val out: JSONObject = if (tok.scope != "full" && Controller.isWriteTool(name)) {
                        JSONObject().put("error", "Este token es de solo lectura")
                    } else {
                        try { Controller.execute(name, args) } catch (e: Exception) { JSONObject().put("error", e.message ?: "error") }
                    }
                    res.put("result", JSONObject()
                        .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", out.toString(2))))
                        .put("isError", out.has("error")))
                }
                else -> res.put("error", JSONObject().put("code", -32601).put("message", "Método no soportado: $method"))
            }
            return res
        }

        fun lanIps(ctx: Context): List<String> {
            val out = ArrayList<String>()
            try {
                for (ni in NetworkInterface.getNetworkInterfaces()) {
                    if (!ni.isUp || ni.isLoopback) continue
                    for (a in ni.inetAddresses) {
                        val h = a.hostAddress ?: continue
                        if (!h.contains(':') && !h.startsWith("10.111.")) out.add(h)
                    }
                }
            } catch (_: Exception) { }
            return out
        }
    }
}

/** Servicio que mantiene vivo el MCP local y la conexión con el servidor remoto. */
class BridgeService : Service() {
    companion object {
        private const val CHANNEL = "nexus_bridge"
        fun start(ctx: Context) {
            try { ctx.startForegroundService(Intent(ctx, BridgeService::class.java)) } catch (_: Exception) { }
        }
        fun stop(ctx: Context) { ctx.stopService(Intent(ctx, BridgeService::class.java)) }
        fun refresh(ctx: Context) {
            stop(ctx)
            if (Store.mcpEnabled || Store.remoteEnabled) start(ctx)
        }
    }

    private var mcp: McpServer? = null
    @Volatile private var alive = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Nexus IA / MCP", NotificationManager.IMPORTANCE_MIN))
        val n = android.app.Notification.Builder(this, CHANNEL)
            .setContentTitle("Nexus: conexión IA activa")
            .setContentText(if (Store.mcpEnabled) "MCP local en puerto ${Store.mcpPort}" else "Control remoto vía servidor")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1002, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1002, n)

        if (!alive) {
            alive = true
            Store.bridgeRunning = true
            if (Store.mcpEnabled && Store.allowed(Features.MCP_LOCAL)) {
                mcp = McpServer(Store.mcpPort, Store.mcpLan).also { it.start() }
            }
            if (Store.remoteEnabled) {
                Thread({
                    while (alive) {
                        try { Remote.syncOnce() } catch (_: Exception) { }
                        try { Thread.sleep(8000) } catch (_: InterruptedException) { break }
                    }
                }, "nexus-remote").start()
            }
            if (!Store.mcpEnabled && !Store.remoteEnabled) stopSelf()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        alive = false
        Store.bridgeRunning = false
        mcp?.stop()
        mcp = null
        super.onDestroy()
    }
}

class BootReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Store.autoStart && Store.wantVpn && Controller.vpnPermissionReady(context)) {
            try { NexusVpnService.start(context) } catch (_: Exception) { }
        }
        if (Store.mcpEnabled || Store.remoteEnabled) BridgeService.start(context)
    }
}
