package com.nexus.firewall

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.VpnService
import org.json.JSONArray
import org.json.JSONObject

class App : Application() {
    companion object {
        lateinit var ctx: Context
            private set
    }

    override fun onCreate() {
        super.onCreate()
        ctx = applicationContext
        Store.init(this)
        if (Store.mcpEnabled || Store.remoteEnabled) BridgeService.start(this)
    }
}

data class AppInfo(val pkg: String, val name: String, val system: Boolean, val uid: Int)

/**
 * Punto único de control: lo usan la interfaz, el servidor MCP local,
 * el control remoto del servidor y el asistente IA.
 */
object Controller {

    fun installedApps(ctx: Context = App.ctx): List<AppInfo> {
        val pm = ctx.packageManager
        return pm.getInstalledApplications(0)
            .filter { it.packageName != ctx.packageName }
            .map {
                AppInfo(
                    it.packageName,
                    try { pm.getApplicationLabel(it).toString() } catch (e: Exception) { it.packageName },
                    (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
                    it.uid
                )
            }
            .sortedBy { it.name.lowercase() }
    }

    fun vpnPermissionReady(ctx: Context = App.ctx): Boolean = VpnService.prepare(ctx) == null

    fun startFirewall(ctx: Context = App.ctx): String {
        if (!vpnPermissionReady(ctx)) return "Falta el permiso VPN: abre Nexus Firewall y pulsa ACTIVAR una vez."
        Store.wantVpn = true
        NexusVpnService.start(ctx)
        return "Firewall activado"
    }

    fun stopFirewall(ctx: Context = App.ctx): String {
        Store.wantVpn = false
        NexusVpnService.stop(ctx)
        return "Firewall detenido"
    }

    fun status(): JSONObject = JSONObject()
        .put("app", "Nexus Firewall")
        .put("version", BuildConfig.VERSION_NAME)
        .put("firewall_activo", Store.vpnRunning)
        .put("consultas_totales", Store.totalQueries.get())
        .put("bloqueadas_totales", Store.totalBlocked.get())
        .put("dominios_en_listas", Store.listDomains.size)
        .put("dominios_bloqueados_por_ti", Store.customBlock.size)
        .put("dominios_permitidos_por_ti", Store.customAllow.size)
        .put("dominios_aprendidos", Store.learned.size)
        .put("apps_bloqueadas", JSONArray(Store.blockedApps.toList()))
        .put("apps_sin_filtro", JSONArray(Store.bypassApps.toList()))
        .put("aprendizaje", Store.learning)
        .put("dns_superior", Store.upstreamDns)
        .put("premium", Store.isPremium())
        .put("device_id", Store.deviceId)

    private fun logsJson(limit: Int, onlyBlocked: Boolean?): JSONArray {
        val a = JSONArray()
        Store.recentLogs(limit, onlyBlocked).forEach {
            a.put(JSONObject().put("t", it.time).put("dominio", it.domain).put("app", it.pkg)
                .put("bloqueado", it.blocked).put("motivo", it.reason))
        }
        return a
    }

    private fun topDomains(limit: Int): JSONArray {
        val a = JSONArray()
        Store.domainHits.entries.sortedByDescending { it.value }.take(limit).forEach {
            a.put(JSONObject().put("dominio", it.key).put("veces", it.value))
        }
        return a
    }

    private fun clean(d: String) = d.trim().lowercase().removePrefix("http://").removePrefix("https://")
        .substringBefore('/').trimEnd('.')

    /** Herramientas expuestas a las IA (MCP local, MCP remoto y asistente). */
    val TOOLS: List<JSONObject> by lazy {
        fun tool(name: String, desc: String, write: Boolean, props: JSONObject = JSONObject(), req: List<String> = emptyList()) =
            JSONObject().put("name", name).put("description", desc).put("write", write)
                .put("inputSchema", JSONObject().put("type", "object").put("properties", props).put("required", JSONArray(req)))
        fun s(d: String) = JSONObject().put("type", "string").put("description", d)
        fun b(d: String) = JSONObject().put("type", "boolean").put("description", d)
        fun n(d: String) = JSONObject().put("type", "integer").put("description", d)
        listOf(
            tool("get_status", "Estado del firewall y estadísticas.", false),
            tool("start_firewall", "Activa el firewall/bloqueador.", true),
            tool("stop_firewall", "Detiene el firewall.", true),
            tool("get_logs", "Últimas consultas DNS registradas.", false,
                JSONObject().put("limit", n("Cantidad, por defecto 100")).put("solo_bloqueadas", b("Solo bloqueadas"))),
            tool("top_domains", "Dominios más consultados.", false, JSONObject().put("limit", n("Cantidad, por defecto 50"))),
            tool("list_apps", "Lista apps instaladas con sus reglas.", false,
                JSONObject().put("incluir_sistema", b("Incluir apps del sistema"))),
            tool("set_app_rule", "Regla de una app: bloquear internet o dejarla pasar sin filtro.", true,
                JSONObject().put("package", s("Nombre de paquete")).put("bloquear_internet", b("true bloquea todo su internet"))
                    .put("sin_filtro", b("true la deja pasar sin bloqueador")), listOf("package")),
            tool("block_domain", "Bloquea un dominio y sus subdominios.", true, JSONObject().put("domain", s("Dominio")), listOf("domain")),
            tool("allow_domain", "Permite siempre un dominio (lista blanca).", true, JSONObject().put("domain", s("Dominio")), listOf("domain")),
            tool("remove_domain_rule", "Quita un dominio de bloqueados, permitidos y aprendidos.", true,
                JSONObject().put("domain", s("Dominio")), listOf("domain")),
            tool("list_rules", "Lista reglas propias, aprendidas y listas activas.", false),
            tool("set_learning", "Activa o desactiva el aprendizaje automático.", true, JSONObject().put("enabled", b("Activado")), listOf("enabled")),
            tool("set_upstream_dns", "Cambia el DNS superior (ej. 1.1.1.1, 9.9.9.9 o el DNS de tu VPN).", true,
                JSONObject().put("dns", s("IP del servidor DNS")), listOf("dns")),
            tool("update_blocklists", "Descarga y actualiza las listas de bloqueo.", true),
            tool("add_blocklist", "Agrega una lista de bloqueo por URL.", true,
                JSONObject().put("name", s("Nombre")).put("url", s("URL hosts o dominios")), listOf("url")),
            tool("clear_logs", "Borra el registro.", true)
        )
    }

    fun isWriteTool(name: String): Boolean = TOOLS.firstOrNull { it.optString("name") == name }?.optBoolean("write", true) ?: true

    /** Ejecuta una herramienta. Llamar fuera del hilo principal. */
    fun execute(name: String, args: JSONObject): JSONObject {
        val r = JSONObject()
        when (name) {
            "get_status" -> return status()
            "start_firewall" -> r.put("resultado", startFirewall())
            "stop_firewall" -> r.put("resultado", stopFirewall())
            "get_logs" -> r.put("registros", logsJson(args.optInt("limit", 100).coerceIn(1, 1000),
                if (args.optBoolean("solo_bloqueadas", false)) true else null))
            "top_domains" -> r.put("dominios", topDomains(args.optInt("limit", 50).coerceIn(1, 500)))
            "list_apps" -> {
                val sys = args.optBoolean("incluir_sistema", false)
                val a = JSONArray()
                installedApps().filter { sys || !it.system }.forEach {
                    a.put(JSONObject().put("package", it.pkg).put("nombre", it.name)
                        .put("internet_bloqueado", Store.blockedApps.contains(it.pkg))
                        .put("sin_filtro", Store.bypassApps.contains(it.pkg)))
                }
                r.put("apps", a)
            }
            "set_app_rule" -> {
                val p = args.optString("package")
                if (p.isEmpty()) return r.put("error", "falta package")
                if (args.has("bloquear_internet")) {
                    if (!Store.allowed(Features.FIREWALL_APPS)) return r.put("error", "Función premium: firewall por app")
                    if (args.optBoolean("bloquear_internet")) Store.blockedApps.add(p) else Store.blockedApps.remove(p)
                }
                if (args.has("sin_filtro")) {
                    if (!Store.allowed(Features.BYPASS_APPS)) return r.put("error", "Función premium: apps sin filtro")
                    if (args.optBoolean("sin_filtro")) Store.bypassApps.add(p) else Store.bypassApps.remove(p)
                    NexusVpnService.restart(App.ctx)
                }
                Store.saveRules()
                r.put("resultado", "Regla aplicada a $p")
            }
            "block_domain" -> {
                if (!Store.allowed(Features.CUSTOM_RULES)) return r.put("error", "Función premium: reglas propias")
                val d = clean(args.optString("domain")); if (d.isEmpty()) return r.put("error", "falta domain")
                Store.customAllow.remove(d); Store.customBlock.add(d); Store.saveRules()
                r.put("resultado", "Bloqueado $d")
            }
            "allow_domain" -> {
                if (!Store.allowed(Features.CUSTOM_RULES)) return r.put("error", "Función premium: reglas propias")
                val d = clean(args.optString("domain")); if (d.isEmpty()) return r.put("error", "falta domain")
                Store.customBlock.remove(d); Store.learned.remove(d); Store.customAllow.add(d); Store.saveRules()
                r.put("resultado", "Permitido $d")
            }
            "remove_domain_rule" -> {
                val d = clean(args.optString("domain"))
                Store.customBlock.remove(d); Store.customAllow.remove(d); Store.learned.remove(d); Store.saveRules()
                r.put("resultado", "Reglas quitadas para $d")
            }
            "list_rules" -> {
                r.put("bloqueados", JSONArray(Store.customBlock.sorted()))
                r.put("permitidos", JSONArray(Store.customAllow.sorted()))
                r.put("aprendidos", JSONArray(Store.learned.sorted()))
                r.put("listas", Store.lists())
            }
            "set_learning" -> { Store.learning = args.optBoolean("enabled", true); r.put("resultado", "Aprendizaje: ${Store.learning}") }
            "set_upstream_dns" -> {
                val d = args.optString("dns").trim()
                if (!Regex("^[0-9a-fA-F:.]+$").matches(d)) return r.put("error", "DNS inválido")
                Store.upstreamDns = d; r.put("resultado", "DNS superior: $d")
            }
            "update_blocklists" -> {
                val (count, errs) = Blocklists.updateAll()
                r.put("dominios", count).put("errores", JSONArray(errs))
            }
            "add_blocklist" -> {
                if (!Store.allowed(Features.CUSTOM_LISTS)) return r.put("error", "Función premium: listas personalizadas")
                val url = args.optString("url").trim()
                if (!url.startsWith("http")) return r.put("error", "URL inválida")
                val a = Store.lists()
                a.put(JSONObject().put("name", args.optString("name", url)).put("url", url).put("on", true))
                Store.saveLists(a)
                r.put("resultado", "Lista agregada. Usa update_blocklists para descargarla.")
            }
            "clear_logs" -> { Store.clearLogs(); r.put("resultado", "Registro borrado") }
            else -> r.put("error", "Herramienta desconocida: $name")
        }
        return r
    }

    fun openVpnSettings(ctx: Context) {
        ctx.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
