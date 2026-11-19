package com.nexus.firewall

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Configuración fija. Cambia SERVER_URL por la dirección de tu servidor en Hostinger. */
object Config {
    /** Ej: https://tudominio.com/nexus_firewall_server.php  (también se puede cambiar dentro de la app) */
    const val SERVER_URL = ""
    const val FAKE_DNS = "10.111.222.2"
    const val VPN_ADDRESS = "10.111.222.1"
    const val DEFAULT_MCP_PORT = 8765
}

/** Funciones que el administrador puede marcar como premium desde el panel. */
object Features {
    const val FIREWALL_APPS = "firewall_apps"
    const val BYPASS_APPS = "bypass_apps"
    const val LEARNING = "learning"
    const val CUSTOM_RULES = "custom_rules"
    const val CUSTOM_LISTS = "custom_lists"
    const val MCP_LOCAL = "mcp_local"
    const val MCP_REMOTE = "mcp_remote"
    const val AI_ASSISTANT = "ai_assistant"
    const val CLONER = "cloner"
    const val THEMES = "themes"
    const val VPN_MANAGER = "vpn_manager"

    val ALL = listOf(
        FIREWALL_APPS, BYPASS_APPS, LEARNING, CUSTOM_RULES, CUSTOM_LISTS,
        MCP_LOCAL, MCP_REMOTE, AI_ASSISTANT, CLONER, THEMES, VPN_MANAGER
    )

    fun label(f: String): String = when (f) {
        FIREWALL_APPS -> "Firewall por aplicación"
        BYPASS_APPS -> "Apps que pasan sin filtro"
        LEARNING -> "Aprendizaje automático de anuncios"
        CUSTOM_RULES -> "Reglas de dominios propias"
        CUSTOM_LISTS -> "Listas de bloqueo personalizadas"
        MCP_LOCAL -> "Servidor MCP local"
        MCP_REMOTE -> "Control remoto MCP vía servidor"
        AI_ASSISTANT -> "Asistente IA"
        CLONER -> "Clonador de aplicaciones"
        THEMES -> "Temas extra"
        VPN_MANAGER -> "Gestor de mis VPN"
        else -> f
    }
}

data class LogEntry(
    val time: Long,
    val domain: String,
    val pkg: String,
    val blocked: Boolean,
    val reason: String
)

data class McpToken(val name: String, val token: String, val scope: String) // scope: "read" | "full"

object Store {
    private lateinit var prefs: SharedPreferences
    private lateinit var filesDir: File

    // Reglas
    val blockedApps: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val bypassApps: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val customBlock: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val customAllow: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val learned: MutableSet<String> = ConcurrentHashMap.newKeySet()

    @Volatile
    var listDomains: Set<String> = emptySet()

    // Registro y estadísticas
    private val logs = ArrayDeque<LogEntry>()
    private const val MAX_LOGS = 3000
    val domainHits: MutableMap<String, Int> = ConcurrentHashMap()
    val totalQueries = AtomicLong(0)
    val totalBlocked = AtomicLong(0)

    @Volatile
    var vpnRunning = false

    @Volatile
    var bridgeRunning = false

    fun init(ctx: Context) {
        prefs = ctx.getSharedPreferences("nexus", Context.MODE_PRIVATE)
        filesDir = ctx.filesDir
        blockedApps.addAll(getSet("blockedApps"))
        bypassApps.addAll(getSet("bypassApps"))
        customBlock.addAll(getSet("customBlock"))
        customAllow.addAll(getSet("customAllow"))
        learned.addAll(getSet("learned"))
        totalQueries.set(prefs.getLong("totalQueries", 0))
        totalBlocked.set(prefs.getLong("totalBlocked", 0))
        if (!prefs.contains("deviceId")) prefs.edit().putString("deviceId", UUID.randomUUID().toString()).apply()
        if (!prefs.contains("lists")) {
            val arr = JSONArray()
            Blocklists.DEFAULTS.forEach { (name, url) ->
                arr.put(JSONObject().put("name", name).put("url", url).put("on", true))
            }
            prefs.edit().putString("lists", arr.toString()).apply()
        }
        Thread { loadListFile() }.start()
    }

    // ---------- utilidades de preferencias ----------
    private fun getSet(key: String): Set<String> = prefs.getStringSet(key, emptySet()) ?: emptySet()

    fun saveRules() {
        prefs.edit()
            .putStringSet("blockedApps", HashSet(blockedApps))
            .putStringSet("bypassApps", HashSet(bypassApps))
            .putStringSet("customBlock", HashSet(customBlock))
            .putStringSet("customAllow", HashSet(customAllow))
            .putStringSet("learned", HashSet(learned))
            .apply()
    }

    fun saveStats() {
        prefs.edit().putLong("totalQueries", totalQueries.get()).putLong("totalBlocked", totalBlocked.get()).apply()
    }

    fun str(key: String, def: String = ""): String = prefs.getString(key, def) ?: def
    fun putStr(key: String, v: String) = prefs.edit().putString(key, v).apply()
    fun bool(key: String, def: Boolean = false): Boolean = prefs.getBoolean(key, def)
    fun putBool(key: String, v: Boolean) = prefs.edit().putBoolean(key, v).apply()
    fun int(key: String, def: Int): Int = prefs.getInt(key, def)
    fun putInt(key: String, v: Int) = prefs.edit().putInt(key, v).apply()

    // ---------- ajustes ----------
    var upstreamDns: String
        get() = str("upstreamDns", "1.1.1.1")
        set(v) = putStr("upstreamDns", v)
    var learning: Boolean
        get() = bool("learning", true)
        set(v) = putBool("learning", v)
    var themeId: String
        get() = str("theme", "rojo")
        set(v) = putStr("theme", v)
    var autoStart: Boolean
        get() = bool("autoStart", true)
        set(v) = putBool("autoStart", v)
    var wantVpn: Boolean
        get() = bool("wantVpn", false)
        set(v) = putBool("wantVpn", v)
    var mcpEnabled: Boolean
        get() = bool("mcpEnabled", false)
        set(v) = putBool("mcpEnabled", v)
    var mcpLan: Boolean
        get() = bool("mcpLan", false)
        set(v) = putBool("mcpLan", v)
    var mcpPort: Int
        get() = int("mcpPort", Config.DEFAULT_MCP_PORT)
        set(v) = putInt("mcpPort", v)
    var remoteEnabled: Boolean
        get() = bool("remoteEnabled", false)
        set(v) = putBool("remoteEnabled", v)
    var serverUrl: String
        get() = str("serverUrl", Config.SERVER_URL).trim()
        set(v) = putStr("serverUrl", v.trim())
    var authToken: String
        get() = str("authToken")
        set(v) = putStr("authToken", v)
    var userEmail: String
        get() = str("userEmail")
        set(v) = putStr("userEmail", v)
    val deviceId: String get() = str("deviceId")

    // ---------- listas de bloqueo ----------
    fun lists(): JSONArray = try { JSONArray(str("lists", "[]")) } catch (e: Exception) { JSONArray() }
    fun saveLists(a: JSONArray) = putStr("lists", a.toString())

    private fun listFile() = File(filesDir, "blocklist.txt")

    fun loadListFile() {
        val f = listFile()
        if (!f.exists()) return
        val set = HashSet<String>(200000)
        f.forEachLine { line -> val d = line.trim(); if (d.isNotEmpty()) set.add(d) }
        listDomains = set
    }

    fun saveListFile(set: Set<String>) {
        listFile().bufferedWriter().use { w -> set.forEach { w.write(it); w.write("\n") } }
        listDomains = set
        putStr("listsUpdated", System.currentTimeMillis().toString())
    }

    // ---------- tokens MCP ----------
    fun mcpTokens(): List<McpToken> {
        val out = ArrayList<McpToken>()
        try {
            val a = JSONArray(str("mcpTokens", "[]"))
            for (i in 0 until a.length()) {
                val o = a.getJSONObject(i)
                out.add(McpToken(o.optString("name"), o.optString("token"), o.optString("scope", "full")))
            }
        } catch (_: Exception) { }
        return out
    }

    fun saveMcpTokens(list: List<McpToken>) {
        val a = JSONArray()
        list.forEach { a.put(JSONObject().put("name", it.name).put("token", it.token).put("scope", it.scope)) }
        putStr("mcpTokens", a.toString())
    }

    // ---------- registro ----------
    fun addLog(e: LogEntry) {
        synchronized(logs) {
            logs.addFirst(e)
            while (logs.size > MAX_LOGS) logs.removeLast()
        }
        domainHits[e.domain] = (domainHits[e.domain] ?: 0) + 1
    }

    fun recentLogs(limit: Int = 500, onlyBlocked: Boolean? = null): List<LogEntry> {
        synchronized(logs) {
            val seq = logs.asSequence().filter { onlyBlocked == null || it.blocked == onlyBlocked }
            return seq.take(limit).toList()
        }
    }

    fun clearLogs() {
        synchronized(logs) { logs.clear() }
        domainHits.clear()
    }

    // ---------- licencia / premium ----------
    fun licenseJson(): JSONObject = try { JSONObject(str("license", "{}")) } catch (e: Exception) { JSONObject() }
    fun saveLicense(o: JSONObject) = putStr("license", o.toString())

    /** Lista de funciones premium definida por el administrador (servidor). */
    fun premiumFeatures(): Set<String> {
        val o = licenseJson()
        val a = o.optJSONArray("premium_features") ?: return if (serverUrl.isEmpty()) emptySet() else Features.ALL.toSet()
        val s = HashSet<String>()
        for (i in 0 until a.length()) s.add(a.optString(i))
        return s
    }

    fun isPremium(): Boolean {
        val o = licenseJson()
        if (!o.optBoolean("premium", false)) return false
        val exp = o.optLong("expires", 0L) // segundos unix; 0 = ilimitado
        return exp == 0L || exp * 1000 > System.currentTimeMillis()
    }

    /** ¿Puede usar esta función? Gratis si no está marcada como premium, o si el usuario es premium.
     *  Si no hay servidor configurado, todo queda desbloqueado (modo dueño). */
    fun allowed(feature: String): Boolean {
        if (serverUrl.isEmpty()) return true
        if (!premiumFeatures().contains(feature)) return true
        return isPremium()
    }

    fun newToken(): String = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "").take(8)

    fun <T> syncList(src: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(src))
}
