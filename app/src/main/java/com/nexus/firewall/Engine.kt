package com.nexus.firewall

import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

/** Descarga y combina listas públicas de bloqueo (formato hosts o lista de dominios). */
object Blocklists {
    val DEFAULTS = listOf(
        "StevenBlack (anuncios + malware)" to "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "AdAway" to "https://adaway.org/hosts.txt",
        "OISD small" to "https://small.oisd.nl/domainswild",
        "Peter Lowe" to "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    )

    private val ipPrefix = Regex("^(0\\.0\\.0\\.0|127\\.0\\.0\\.1|::1?|::)\\s+")
    private val validDomain = Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

    fun parseLine(raw: String): String? {
        var l = raw.trim().lowercase()
        if (l.isEmpty() || l.startsWith("#") || l.startsWith("!") || l.startsWith("[")) return null
        val hash = l.indexOf('#'); if (hash > 0) l = l.substring(0, hash).trim()
        l = l.replace(ipPrefix, "")
        if (l.startsWith("||")) l = l.removePrefix("||").substringBefore('^')
        if (l.startsWith("*.")) l = l.removePrefix("*.")
        l = l.trim().trimEnd('.')
        if (l == "localhost" || l == "localhost.localdomain" || l == "broadcasthost" || l == "local" || l == "0.0.0.0") return null
        if (l.contains(' ') || l.contains('\t')) l = l.substringBefore(' ').substringBefore('\t')
        return if (validDomain.matches(l)) l else null
    }

    /** Devuelve (dominiosTotales, errores). Bloquea el hilo: llamar fuera del hilo principal. */
    fun updateAll(progress: (String) -> Unit = {}): Pair<Int, List<String>> {
        val lists: JSONArray = Store.lists()
        val result = HashSet<String>(250000)
        val errors = ArrayList<String>()
        for (i in 0 until lists.length()) {
            val o = lists.getJSONObject(i)
            if (!o.optBoolean("on", true)) continue
            val name = o.optString("name")
            val url = o.optString("url")
            progress("Descargando $name…")
            try {
                val c = URL(url).openConnection() as HttpURLConnection
                c.connectTimeout = 15000
                c.readTimeout = 30000
                c.setRequestProperty("User-Agent", "NexusFirewall/1.0")
                if (c.responseCode !in 200..299) throw Exception("HTTP ${c.responseCode}")
                var count = 0
                c.inputStream.bufferedReader().useLines { seq ->
                    seq.forEach { line -> parseLine(line)?.let { if (result.add(it)) count++ } }
                }
                o.put("count", count)
                o.put("error", "")
            } catch (e: Exception) {
                errors.add("$name: ${e.message}")
                o.put("error", e.message ?: "error")
            }
        }
        Store.saveLists(lists)
        if (result.isNotEmpty()) Store.saveListFile(result)
        progress("Listo: ${result.size} dominios")
        return Pair(result.size, errors)
    }
}

/** Aprendizaje: detecta dominios de anuncios/rastreo por patrones y los bloquea solo. */
object Learner {
    private val strongTokens = setOf(
        "ads", "adserver", "adservice", "adservices", "adsystem", "adserving", "advert", "adverts",
        "advertising", "advertiser", "doubleclick", "googlesyndication", "googleadservices", "adnxs",
        "adsrvr", "adform", "adtech", "admob", "adcolony", "applovin", "unityads", "chartboost", "vungle",
        "inmobi", "mopub", "ironsrc", "appsflyer", "adjust", "kochava", "taboola", "outbrain", "criteo",
        "pubmatic", "rubiconproject", "openx", "smaato", "startapp", "popads", "popunder", "propellerads",
        "tracking", "tracker", "trackers", "telemetry", "analytics", "metrics", "pixel", "beacon",
        "banner", "banners", "measurement", "affiliate", "clicktrack", "adzerk", "moatads", "scorecardresearch", "quantserve"
    )
    private val adNumbered = Regex("^(ad|ads|adv|track|trk)[0-9-]+$")

    /** Devuelve el motivo si parece anuncio/rastreador, o null. */
    fun classify(domain: String): String? {
        val labels = domain.split('.')
        if (labels.size < 2) return null
        val body = labels.dropLast(1) // sin TLD
        for (lab in body) {
            if (lab in strongTokens) return "patrón '$lab'"
            if (adNumbered.matches(lab)) return "patrón '$lab'"
            for (part in lab.split('-')) if (part in strongTokens) return "patrón '$part'"
        }
        return null
    }

    fun rootOf(domain: String): String {
        val l = domain.split('.')
        return if (l.size <= 2) domain else l.takeLast(2).joinToString(".")
    }
}

/** Motor de decisión del firewall. */
object Engine {
    data class Verdict(val block: Boolean, val reason: String)

    private fun matches(set: Set<String>, domain: String): Boolean {
        var d = domain
        while (true) {
            if (set.contains(d)) return true
            val i = d.indexOf('.')
            if (i < 0) return false
            d = d.substring(i + 1)
            if (!d.contains('.')) return set.contains(d)
        }
    }

    fun decide(domainRaw: String, pkg: String): Verdict {
        val domain = domainRaw.lowercase().trimEnd('.')
        if (pkg.isNotEmpty() && Store.blockedApps.contains(pkg) && Store.allowed(Features.FIREWALL_APPS))
            return Verdict(true, "app bloqueada")
        if (matches(Store.customAllow, domain)) return Verdict(false, "permitido por ti")
        if (matches(Store.customBlock, domain)) return Verdict(true, "bloqueado por ti")
        if (matches(Store.learned, domain)) return Verdict(true, "aprendido")
        if (matches(Store.listDomains, domain)) return Verdict(true, "lista de bloqueo")
        if (Store.learning && Store.allowed(Features.LEARNING)) {
            val why = Learner.classify(domain)
            if (why != null) {
                Store.learned.add(domain)
                Store.saveRules()
                return Verdict(true, "aprendido ($why)")
            }
        }
        return Verdict(false, "permitido")
    }
}
