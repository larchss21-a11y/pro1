package com.nexus.firewall

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

class MainActivity : UiActivity() {

    private val REQ_VPN = 77
    private lateinit var body: FrameLayout
    private lateinit var tabsRow: LinearLayout
    private lateinit var headerStatus: TextView
    private var currentTab = "panel"
    private val handler = Handler(Looper.getMainLooper())
    private var ticker: Runnable? = null
    private val iconCache = ConcurrentHashMap<String, Drawable>()
    private var appsCache: List<AppInfo>? = null

    private val tabs = listOf(
        "panel" to "⚡ Panel", "apps" to "📱 Apps", "logs" to "📜 Registro", "rules" to "🛡 Reglas",
        "clone" to "🧬 Clonar", "ai" to "🤖 IA / MCP", "account" to "👑 Cuenta", "settings" to "🎨 Ajustes"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = pal.bg
        window.navigationBarColor = pal.bg
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 5)

        val root = col().apply { setBackgroundColor(pal.bg) }
        // Encabezado
        val header = row().apply { setPadding(dp(16), dp(14), dp(16), dp(6)) }
        val logo = tv("NEXUS", 22f, pal.accent, true)
        val logo2 = tv(" FIREWALL", 22f, pal.text, true)
        header.addView(logo); header.addView(logo2)
        header.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
        headerStatus = tv("", 12f, pal.sub, true)
        header.addView(headerStatus)
        root.addView(header)

        tabsRow = row().apply { setPadding(dp(8), dp(4), dp(8), dp(8)) }
        val hs = HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(tabsRow) }
        root.addView(hs)

        body = FrameLayout(this)
        root.addView(body, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        currentTab = savedInstanceState?.getString("tab") ?: intent.getStringExtra("tab") ?: "panel"
        showTab(currentTab)
        if (Store.serverUrl.isNotEmpty() && Store.authToken.isNotEmpty()) bg {
            try { Remote.refreshLicense() } catch (_: Exception) { }
            ui { updateHeader() }
        }
        if (Store.listDomains.isEmpty() && Store.str("listsUpdated").isEmpty()) bg {
            try { Blocklists.updateAll() } catch (_: Exception) { }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("tab", currentTab)
    }

    override fun onResume() { super.onResume(); updateHeader() }
    override fun onDestroy() { stopTicker(); super.onDestroy() }

    private fun updateHeader() {
        val st = if (Store.vpnRunning) "● ACTIVO" else "○ APAGADO"
        val pr = if (Store.serverUrl.isEmpty()) "" else if (Store.isPremium()) "  👑 PREMIUM" else "  GRATIS"
        headerStatus.text = st + pr
        headerStatus.setTextColor(if (Store.vpnRunning) pal.accent else pal.sub)
    }

    private fun renderTabs() {
        tabsRow.removeAllViews()
        for ((id, label) in tabs) {
            val sel = id == currentTab
            val t = tv(label, 13f, if (sel) Color.WHITE else pal.sub, true).apply {
                background = if (sel) rounded(pal.accent, 20) else rounded(pal.card, 20)
                setPadding(dp(14), dp(8), dp(14), dp(8))
                setOnClickListener { showTab(id) }
            }
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.setMargins(dp(4), 0, dp(4), 0)
            tabsRow.addView(t, lp)
        }
    }

    private fun stopTicker() { ticker?.let { handler.removeCallbacks(it) }; ticker = null }

    private fun startTicker(ms: Long, block: () -> Unit) {
        stopTicker()
        val r = object : Runnable { override fun run() { block(); handler.postDelayed(this, ms) } }
        ticker = r
        handler.postDelayed(r, ms)
    }

    fun showTab(id: String) {
        currentTab = id
        stopTicker()
        renderTabs()
        updateHeader()
        body.removeAllViews()
        val v: View = when (id) {
            "apps" -> appsScreen()
            "logs" -> logsScreen()
            "rules" -> rulesScreen()
            "clone" -> cloneScreen()
            "ai" -> aiScreen()
            "account" -> accountScreen()
            "settings" -> settingsScreen()
            else -> panelScreen()
        }
        body.addView(v, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }

    /** Si la función es premium y no la tiene, muestra aviso. */
    private fun gate(feature: String): Boolean {
        if (Store.allowed(feature)) return true
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("👑 Función Premium")
            .setMessage("“${Features.label(feature)}” es parte de Premium. Hazte Premium desde la pestaña Cuenta.")
            .setPositiveButton("Ver planes") { _, _ -> showTab("account") }
            .setNegativeButton("Cerrar", null).show()
        return false
    }

    // ======================= PANEL =======================
    private fun panelScreen(): View {
        val c = col()
        val power = tv(if (Store.vpnRunning) "DETENER" else "ACTIVAR", 22f, Color.WHITE, true).apply {
            gravity = Gravity.CENTER
            background = GradientDrawableCircle(if (Store.vpnRunning) pal.accent else pal.card, pal.accent, dp(4))
            setOnClickListener { toggleVpn() }
        }
        val size = if (isWide()) dp(220) else dp(170)
        val pw = FrameLayout(this)
        pw.addView(power, FrameLayout.LayoutParams(size, size, Gravity.CENTER))
        c.addView(pw, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, size + dp(24)))

        val statsCard = card()
        val stats = tv("", 15f)
        statsCard.addView(head("Estadísticas"))
        statsCard.addView(stats)
        c.addView(statsCard)
        fun refresh() {
            val q = Store.totalQueries.get(); val b = Store.totalBlocked.get()
            val pct = if (q > 0) (b * 100.0 / q) else 0.0
            stats.text = "Consultas: $q\nBloqueadas: $b (${String.format(Locale.US, "%.1f", pct)}%)\n" +
                "Dominios en listas: ${Store.listDomains.size}\nAprendidos: ${Store.learned.size}   Tuyos: ${Store.customBlock.size}\n" +
                "Apps bloqueadas: ${Store.blockedApps.size}   Sin filtro: ${Store.bypassApps.size}\nDNS superior: ${Store.upstreamDns}"
            power.text = if (Store.vpnRunning) "DETENER" else "ACTIVAR"
            power.background = GradientDrawableCircle(if (Store.vpnRunning) pal.accent else pal.card, pal.accent, dp(4))
            updateHeader()
        }
        refresh()
        startTicker(1500) { refresh() }

        val tips = card()
        tips.addView(head("Para bloquear al máximo"))
        tips.addView(sub("• Desactiva el “DNS privado” de Android (Ajustes › Conexiones › Más ajustes › DNS privado › Desactivado), si no, las apps se saltan el filtro.\n" +
            "• En Chrome: Ajustes › Privacidad › Usar DNS seguro › Desactivado.\n" +
            "• Activa “VPN siempre activa” para Nexus en los ajustes VPN de Android.\n" +
            "• Algunos anuncios (como los de YouTube) vienen del mismo servidor que el video: ningún bloqueador por DNS puede quitarlos sin romper la app."))
        tips.addView(space())
        tips.addView(wrapRow(listOf(
            smallBtn("Ajustes de red") { try { startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) } catch (_: Exception) { } },
            smallBtn("Ajustes VPN") { Controller.openVpnSettings(this) },
            smallBtn("Actualizar listas", true) { updateListsUi(null) }
        )))
        c.addView(tips)

        // Mis VPN
        val vpnCard = card()
        vpnCard.addView(head("Mis VPN"))
        vpnCard.addView(sub("Android solo permite una VPN a la vez. Aquí ves tus VPN instaladas y cambias a una con un toque (Nexus se pausa). Si tu VPN tiene DNS propio, ponlo como DNS superior en Reglas para usarlo con Nexus."))
        val pm = packageManager
        val vpnApps = try {
            pm.queryIntentServices(Intent(VpnService.SERVICE_INTERFACE), 0)
                .map { it.serviceInfo.packageName }.distinct().filter { it != packageName }
        } catch (e: Exception) { emptyList() }
        if (vpnApps.isEmpty()) vpnCard.addView(sub("\nNo se encontraron otras apps VPN instaladas."))
        for (p in vpnApps) {
            val r = row().apply { setPadding(0, dp(6), 0, dp(6)) }
            val name = try { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() } catch (e: Exception) { p }
            r.addView(tv(name, 14f, pal.text, true), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            r.addView(smallBtn("Usar esta VPN", true) {
                if (!gate(Features.VPN_MANAGER)) return@smallBtn
                Controller.stopFirewall(this)
                val li = pm.getLaunchIntentForPackage(p)
                if (li != null) startActivity(li) else toast("Esa VPN no tiene pantalla de inicio")
            })
            vpnCard.addView(r)
        }
        c.addView(vpnCard)
        return scroll(c)
    }

    private fun GradientDrawableCircle(fill: Int, stroke: Int, w: Int) =
        android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(fill); setStroke(w, stroke)
        }

    private fun toggleVpn() {
        if (Store.vpnRunning) {
            Controller.stopFirewall(this)
            handler.postDelayed({ if (currentTab == "panel") showTab("panel") }, 600)
            return
        }
        val prep = VpnService.prepare(this)
        if (prep != null) startActivityForResult(prep, REQ_VPN) else onActivityResult(REQ_VPN, RESULT_OK, null)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                Store.wantVpn = true
                NexusVpnService.start(this)
                handler.postDelayed({ if (currentTab == "panel") showTab("panel") }, 700)
            } else toast("Necesito el permiso VPN para filtrar (es local, nada sale de tu teléfono).")
        }
    }

    private fun updateListsUi(label: TextView?) {
        toast("Actualizando listas de bloqueo…")
        bg {
            val (n, errs) = Blocklists.updateAll { msg -> ui { label?.text = msg } }
            ui {
                toast("Listas: $n dominios" + if (errs.isNotEmpty()) "\nErrores: ${errs.joinToString()}" else "")
                if (currentTab == "rules") showTab("rules")
            }
        }
    }

    // ======================= APPS =======================
    private fun appsScreen(): View {
        val c = col().apply { setPadding(dp(12), 0, dp(12), 0) }
        c.addView(sub("🌐 Internet: si lo apagas, la app queda sin internet.  🛡 Filtro: si lo apagas, la app pasa sin bloqueador de anuncios (tú decides)."))
        val search = input("Buscar app…")
        c.addView(search)
        var showSystem = false
        val sysBtn = smallBtn("Mostrar apps del sistema") { }
        c.addView(sysBtn)
        val list = ListView(this).apply { divider = null; setBackgroundColor(Color.TRANSPARENT) }
        c.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        val loading = sub("Cargando apps…")
        c.addView(loading)

        var all: List<AppInfo> = emptyList()
        val shown = ArrayList<AppInfo>()
        val adapter = object : BaseAdapter() {
            override fun getCount() = shown.size
            override fun getItem(p: Int): Any = shown[p]
            override fun getItemId(p: Int) = p.toLong()
            override fun getView(p: Int, convert: View?, parent: ViewGroup?): View = appRow(shown[p])
        }
        list.adapter = adapter
        fun filter() {
            val q = search.text.toString().trim().lowercase()
            shown.clear()
            shown.addAll(all.filter { (showSystem || !it.system) && (q.isEmpty() || it.name.lowercase().contains(q) || it.pkg.contains(q)) })
            adapter.notifyDataSetChanged()
            loading.text = "${shown.size} apps"
        }
        sysBtn.setOnClickListener {
            showSystem = !showSystem
            sysBtn.text = if (showSystem) "Ocultar apps del sistema" else "Mostrar apps del sistema"
            filter()
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            override fun afterTextChanged(s: Editable?) { filter() }
        })
        bg {
            val apps = appsCache ?: Controller.installedApps(this).also { appsCache = it }
            ui { all = apps; filter() }
        }
        return c
    }

    private fun icon(pkg: String): Drawable? = iconCache[pkg] ?: try {
        packageManager.getApplicationIcon(pkg).also { iconCache[pkg] = it }
    } catch (e: Exception) { null }

    private fun appRow(a: AppInfo): View {
        val r = row().apply {
            background = rounded(pal.card, 12)
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        val iv = ImageView(this)
        icon(a.pkg)?.let { iv.setImageDrawable(it) }
        r.addView(iv, LinearLayout.LayoutParams(dp(40), dp(40)))
        val texts = col().apply { setPadding(dp(10), 0, dp(6), 0) }
        texts.addView(tv(a.name, 14f, pal.text, true))
        texts.addView(sub(a.pkg).apply { textSize = 11f })
        r.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        val blocked = Store.blockedApps.contains(a.pkg)
        val bypass = Store.bypassApps.contains(a.pkg)
        val net = smallBtn(if (blocked) "🌐 NO" else "🌐 SÍ", !blocked) {
            if (!gate(Features.FIREWALL_APPS)) return@smallBtn
            if (Store.blockedApps.contains(a.pkg)) Store.blockedApps.remove(a.pkg) else Store.blockedApps.add(a.pkg)
            Store.saveRules(); showTabKeepScroll()
        }
        val filt = smallBtn(if (bypass) "🛡 NO" else "🛡 SÍ", !bypass) {
            if (!gate(Features.BYPASS_APPS)) return@smallBtn
            if (Store.bypassApps.contains(a.pkg)) Store.bypassApps.remove(a.pkg) else Store.bypassApps.add(a.pkg)
            Store.saveRules()
            NexusVpnService.restart(this)
            showTabKeepScroll()
        }
        val btns = col()
        btns.addView(net); btns.addView(space(4)); btns.addView(filt)
        r.addView(btns)
        val wrap = FrameLayout(this).apply { setPadding(0, dp(3), 0, dp(3)) }
        wrap.addView(r)
        return wrap
    }

    private fun showTabKeepScroll() {
        // Repinta la lista conservando la posición
        val lv = findListView(body) ?: return
        (lv.adapter as? BaseAdapter)?.notifyDataSetChanged()
    }

    private fun findListView(v: View): ListView? {
        if (v is ListView) return v
        if (v is ViewGroup) for (i in 0 until v.childCount) { findListView(v.getChildAt(i))?.let { return it } }
        return null
    }

    // ======================= REGISTRO =======================
    private fun logsScreen(): View {
        val c = col().apply { setPadding(dp(12), 0, dp(12), 0) }
        var mode: Boolean? = null
        var paused = false
        val shown = ArrayList<LogEntry>()
        val fmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        val labelCache = HashMap<String, String>()
        fun appLabel(p: String): String {
            if (p.isEmpty()) return "?"
            return labelCache.getOrPut(p) {
                try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(p, 0)).toString() } catch (e: Exception) { p }
            }
        }
        val adapter = object : BaseAdapter() {
            override fun getCount() = shown.size
            override fun getItem(p: Int): Any = shown[p]
            override fun getItemId(p: Int) = p.toLong()
            override fun getView(p: Int, convert: View?, parent: ViewGroup?): View {
                val e = shown[p]
                val v = col().apply { setPadding(dp(10), dp(6), dp(10), dp(6)) }
                v.addView(tv((if (e.blocked) "⛔ " else "✅ ") + e.domain, 13.5f, if (e.blocked) pal.accent else pal.text, true))
                v.addView(sub("${fmt.format(Date(e.time))} · ${appLabel(e.pkg)} · ${e.reason}").apply { textSize = 11f })
                return v
            }
        }
        val list = ListView(this).apply { this.adapter = adapter; divider = null }
        fun refresh() {
            if (paused) return
            shown.clear(); shown.addAll(Store.recentLogs(800, mode)); adapter.notifyDataSetChanged()
        }
        c.addView(wrapRow(listOf(
            smallBtn("Todos", true) { mode = null; refresh() },
            smallBtn("Bloqueados") { mode = true; refresh() },
            smallBtn("Permitidos") { mode = false; refresh() },
            smallBtn("Borrar") { Store.clearLogs(); refresh() }
        )))
        val pauseBtn = smallBtn("⏸ Pausar") { }
        pauseBtn.setOnClickListener { paused = !paused; pauseBtn.text = if (paused) "▶ Seguir" else "⏸ Pausar" }
        c.addView(pauseBtn)
        c.addView(sub("Toca un dominio para bloquearlo, permitirlo o bloquear la app que lo pidió."))
        c.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        list.setOnItemClickListener { _, _, pos, _ -> if (pos < shown.size) logActions(shown[pos]) { refresh() } }
        refresh()
        startTicker(2000) { refresh() }
        return c
    }

    private fun logActions(e: LogEntry, done: () -> Unit) {
        val root = Learner.rootOf(e.domain)
        val opts = arrayOf(
            "⛔ Bloquear ${e.domain}", "⛔ Bloquear todo $root", "✅ Permitir siempre ${e.domain}",
            "🧹 Quitar reglas de ${e.domain}", "📵 Quitar internet a la app", "📋 Copiar dominio"
        )
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(e.domain)
            .setItems(opts) { _, which ->
                val res: JSONObject? = when (which) {
                    0 -> if (gate(Features.CUSTOM_RULES)) Controller.execute("block_domain", JSONObject().put("domain", e.domain)) else null
                    1 -> if (gate(Features.CUSTOM_RULES)) Controller.execute("block_domain", JSONObject().put("domain", root)) else null
                    2 -> if (gate(Features.CUSTOM_RULES)) Controller.execute("allow_domain", JSONObject().put("domain", e.domain)) else null
                    3 -> Controller.execute("remove_domain_rule", JSONObject().put("domain", e.domain))
                    4 -> if (e.pkg.isNotEmpty() && gate(Features.FIREWALL_APPS))
                        Controller.execute("set_app_rule", JSONObject().put("package", e.pkg).put("bloquear_internet", true)) else null
                    else -> { copy(e.domain); null }
                }
                res?.let { toast(it.optString("resultado", it.optString("error"))) }
                done()
            }.show()
    }

    // ======================= REGLAS =======================
    private fun rulesScreen(): View {
        val c = col()
        val learnCard = card()
        learnCard.addView(switchRow("Aprendizaje automático",
            "Detecta anuncios y rastreadores nuevos que no estén en las listas y los bloquea solo.", Store.learning) {
            if (it && !gate(Features.LEARNING)) { showTab("rules"); return@switchRow }
            Store.learning = it
        })
        learnCard.addView(sub("Aprendidos: ${Store.learned.size}"))
        learnCard.addView(space())
        learnCard.addView(wrapRow(listOf(
            smallBtn("Ver aprendidos") { showDomainSet("Aprendidos", Store.learned) },
            smallBtn("🤖 Analizar con IA", true) { aiClassify() }
        )))
        c.addView(learnCard)

        // DNS superior
        val dnsCard = card()
        dnsCard.addView(head("DNS superior"))
        dnsCard.addView(sub("A dónde se reenvían las consultas permitidas. Actual: ${Store.upstreamDns}"))
        val presets = listOf("1.1.1.1" to "Cloudflare", "9.9.9.9" to "Quad9", "8.8.8.8" to "Google", "94.140.14.14" to "AdGuard")
        dnsCard.addView(wrapRow(presets.map { (ip, n) ->
            smallBtn("$n\n$ip", ip == Store.upstreamDns) { Store.upstreamDns = ip; showTab("rules") }
        }))
        val customDns = input("Otro DNS (ej. el DNS de tu VPN)", "")
        dnsCard.addView(customDns)
        dnsCard.addView(smallBtn("Usar este DNS") {
            val r = Controller.execute("set_upstream_dns", JSONObject().put("dns", customDns.text.toString()))
            toast(r.optString("resultado", r.optString("error"))); showTab("rules")
        })
        c.addView(dnsCard)

        // Listas
        val listsCard = card()
        listsCard.addView(head("Listas de bloqueo"))
        val prog = sub("Total en memoria: ${Store.listDomains.size} dominios")
        listsCard.addView(prog)
        val lists = Store.lists()
        for (i in 0 until lists.length()) {
            val o = lists.getJSONObject(i)
            val info = "${o.optInt("count", 0)} dominios" + (if (o.optString("error").isNotEmpty()) " · error: ${o.optString("error")}" else "")
            listsCard.addView(switchRow(o.optString("name"), info + "\n" + o.optString("url"), o.optBoolean("on", true)) { on ->
                val a = Store.lists(); a.getJSONObject(i).put("on", on); Store.saveLists(a)
            })
            listsCard.addView(smallBtn("Quitar lista") {
                val a = Store.lists(); val n = JSONArray()
                for (k in 0 until a.length()) if (k != i) n.put(a.get(k))
                Store.saveLists(n); showTab("rules")
            })
        }
        val ln = input("Nombre de la lista")
        val lu = input("URL (formato hosts o lista de dominios)")
        listsCard.addView(ln); listsCard.addView(lu)
        listsCard.addView(wrapRow(listOf(
            smallBtn("Agregar lista") {
                if (!gate(Features.CUSTOM_LISTS)) return@smallBtn
                val r = Controller.execute("add_blocklist", JSONObject().put("name", ln.text.toString().ifBlank { lu.text.toString() }).put("url", lu.text.toString()))
                toast(r.optString("resultado", r.optString("error"))); showTab("rules")
            },
            smallBtn("Actualizar ahora", true) { updateListsUi(prog) }
        )))
        c.addView(listsCard)

        // Reglas propias
        c.addView(domainRuleCard("Dominios bloqueados por ti", Store.customBlock, "block_domain"))
        c.addView(domainRuleCard("Dominios permitidos (lista blanca)", Store.customAllow, "allow_domain"))

        // Exportar / importar
        val exp = card()
        exp.addView(head("Respaldo de reglas"))
        exp.addView(wrapRow(listOf(
            smallBtn("Exportar (copiar)") { copy(exportRules().toString()) },
            smallBtn("Importar (pegar)") { importRulesDialog() }
        )))
        c.addView(exp)
        return scroll(c)
    }

    private fun domainRuleCard(t: String, set: MutableSet<String>, tool: String): View {
        val k = card()
        k.addView(head("$t (${set.size})"))
        val inp = input("ejemplo.com")
        k.addView(inp)
        k.addView(smallBtn("Agregar", true) {
            if (!gate(Features.CUSTOM_RULES)) return@smallBtn
            val r = Controller.execute(tool, JSONObject().put("domain", inp.text.toString()))
            toast(r.optString("resultado", r.optString("error"))); showTab("rules")
        })
        set.sorted().take(300).forEach { d ->
            val r = row().apply { setPadding(0, dp(4), 0, dp(4)) }
            r.addView(tv(d, 13f), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            r.addView(smallBtn("✕") { set.remove(d); Store.saveRules(); showTab("rules") })
            k.addView(r)
        }
        if (set.size > 300) k.addView(sub("…y ${set.size - 300} más"))
        return k
    }

    private fun showDomainSet(t: String, set: MutableSet<String>) {
        val items = set.sorted().toTypedArray()
        if (items.isEmpty()) { dialog(t, "Todavía no hay dominios."); return }
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("$t (${items.size}) — toca para permitir")
            .setItems(items) { _, w ->
                val d = items[w]
                set.remove(d); Store.customAllow.add(d); Store.saveRules()
                toast("$d ahora está permitido")
            }.setPositiveButton("Cerrar", null).show()
    }

    private fun exportRules(): JSONObject = JSONObject()
        .put("blockedApps", JSONArray(Store.blockedApps.toList()))
        .put("bypassApps", JSONArray(Store.bypassApps.toList()))
        .put("customBlock", JSONArray(Store.customBlock.toList()))
        .put("customAllow", JSONArray(Store.customAllow.toList()))
        .put("learned", JSONArray(Store.learned.toList()))
        .put("lists", Store.lists())
        .put("upstreamDns", Store.upstreamDns)

    private fun importRulesDialog() {
        val e = input("Pega aquí el respaldo JSON")
        e.isSingleLine = false; e.minLines = 4
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Importar reglas").setView(e)
            .setPositiveButton("Importar") { _, _ ->
                try {
                    val o = JSONObject(e.text.toString())
                    fun into(key: String, set: MutableSet<String>) {
                        val a = o.optJSONArray(key) ?: return
                        for (i in 0 until a.length()) set.add(a.getString(i))
                    }
                    into("blockedApps", Store.blockedApps); into("bypassApps", Store.bypassApps)
                    into("customBlock", Store.customBlock); into("customAllow", Store.customAllow); into("learned", Store.learned)
                    o.optJSONArray("lists")?.let { Store.saveLists(it) }
                    if (o.has("upstreamDns")) Store.upstreamDns = o.getString("upstreamDns")
                    Store.saveRules(); NexusVpnService.restart(this)
                    toast("Reglas importadas"); showTab("rules")
                } catch (ex: Exception) { toast("JSON inválido: ${ex.message}") }
            }.setNegativeButton("Cancelar", null).show()
    }

    private fun aiClassify() {
        if (!gate(Features.AI_ASSISTANT)) return
        if (Store.authToken.isEmpty()) { toast("Inicia sesión en Cuenta para usar la IA del servidor"); return }
        val candidates = Store.domainHits.keys.filter { d ->
            Engine.decide(d, "").let { !it.block } && !Store.customAllow.contains(d)
        }.take(250)
        if (candidates.isEmpty()) { toast("Primero navega un poco para tener dominios que analizar"); return }
        toast("Analizando ${candidates.size} dominios con IA…")
        bg {
            try {
                val r = Remote.api("ai_classify", JSONObject().put("domains", JSONArray(candidates)), 90000)
                val ads = r.optJSONArray("ads") ?: JSONArray()
                var n = 0
                for (i in 0 until ads.length()) {
                    val d = ads.optString(i).lowercase()
                    if (d in candidates && Store.learned.add(d)) n++
                }
                Store.saveRules()
                ui { dialog("IA", "La IA marcó $n dominios como anuncios/rastreadores y ya se bloquean.\n\n${r.optString("note")}") }
            } catch (e: Exception) { ui { dialog("IA", "Error: ${e.message}") } }
        }
    }

    // ======================= CLONADOR =======================
    private fun cloneScreen(): View {
        val c = col()
        val info = card()
        info.addView(head("Clonador de apps"))
        info.addView(sub("Nexus crea un “espacio clonado” (perfil de trabajo de Android). Ahí puedes tener una segunda copia de tus apps con otra cuenta (WhatsApp, Instagram, juegos…). Los clones aparecen con un maletín 💼 en el cajón de apps.\n\nNota: Android permite un solo espacio clonado (una copia extra por app). Si ya usas otro perfil de trabajo, primero quítalo. Los clones no pasan por el firewall del perfil personal."))
        c.addView(info)

        if (Cloner.insideProfile(this)) {
            val k = card()
            k.addView(head("Estás dentro del espacio clonado"))
            k.addView(btn("Eliminar espacio clonado") {
                AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle("¿Eliminar?").setMessage("Se borran todas las apps clonadas y sus datos.")
                    .setPositiveButton("Eliminar") { _, _ -> toast(Cloner.applyInProfile(this, "", "wipe")) }
                    .setNegativeButton("Cancelar", null).show()
            })
            c.addView(k)
            return scroll(c)
        }

        val exists = Cloner.profileExists(this)
        val st = card()
        st.addView(tv(if (exists) "✅ Espacio clonado listo" else "Espacio clonado: no creado", 15f, pal.text, true))
        if (!exists) {
            st.addView(space())
            st.addView(btn("Crear espacio clonado") {
                if (!gate(Features.CLONER)) return@btn
                val i = Cloner.provisioningIntent(this)
                if (i == null) dialog("Clonador", "Este teléfono no permite crear perfiles de trabajo.")
                else try { startActivityForResult(i, 88) } catch (e: Exception) { dialog("Clonador", "Error: ${e.message}") }
            })
        } else {
            st.addView(space())
            st.addView(smallBtn("Eliminar espacio clonado") {
                AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                    .setTitle("¿Eliminar espacio clonado?").setMessage("Se borran todas las apps clonadas y sus datos.")
                    .setPositiveButton("Eliminar") { _, _ -> Cloner.sendToProfile(this, "", "wipe") }
                    .setNegativeButton("Cancelar", null).show()
            })
        }
        c.addView(st)

        if (exists) {
            val listCard = card()
            listCard.addView(head("Elige qué apps clonar"))
            val holder = col()
            listCard.addView(holder)
            holder.addView(sub("Cargando…"))
            c.addView(listCard)
            bg {
                val apps = (appsCache ?: Controller.installedApps(this).also { appsCache = it }).filter { !it.system }
                ui {
                    holder.removeAllViews()
                    for (a in apps) {
                        val r = row().apply { setPadding(0, dp(5), 0, dp(5)) }
                        val iv = ImageView(this); icon(a.pkg)?.let { iv.setImageDrawable(it) }
                        r.addView(iv, LinearLayout.LayoutParams(dp(34), dp(34)))
                        r.addView(tv("  " + a.name, 14f), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                        r.addView(smallBtn("Clonar", true) { if (gate(Features.CLONER)) Cloner.sendToProfile(this, a.pkg, "clone") })
                        r.addView(View(this), LinearLayout.LayoutParams(dp(6), 1))
                        r.addView(smallBtn("Quitar") { Cloner.sendToProfile(this, a.pkg, "hide") })
                        holder.addView(r)
                    }
                }
            }
        }
        return scroll(c)
    }

    // ======================= IA / MCP =======================
    private fun aiScreen(): View {
        val c = col()
        // MCP local
        val local = card()
        local.addView(head("Servidor MCP en el teléfono"))
        local.addView(sub("Conecta tus IA (una o varias) para que controlen el firewall. Cada IA usa su propio token; puedes darle solo lectura o control total."))
        local.addView(switchRow("Activar MCP local", "Puerto ${Store.mcpPort}", Store.mcpEnabled) {
            if (it && !gate(Features.MCP_LOCAL)) { showTab("ai"); return@switchRow }
            Store.mcpEnabled = it; BridgeService.refresh(this); handler.postDelayed({ showTab("ai") }, 400)
        })
        local.addView(switchRow("Permitir desde mi red Wi-Fi", "Para conectar una IA desde tu PC en la misma red", Store.mcpLan) {
            Store.mcpLan = it; BridgeService.refresh(this); handler.postDelayed({ showTab("ai") }, 400)
        })
        val portIn = input("Puerto", Store.mcpPort.toString())
        portIn.inputType = android.text.InputType.TYPE_CLASS_NUMBER
        local.addView(portIn)
        local.addView(smallBtn("Guardar puerto") {
            val p = portIn.text.toString().toIntOrNull()
            if (p == null || p < 1024 || p > 65535) toast("Puerto entre 1024 y 65535")
            else { Store.mcpPort = p; BridgeService.refresh(this); showTab("ai") }
        })
        val urls = mutableListOf("http://127.0.0.1:${Store.mcpPort}/mcp")
        if (Store.mcpLan) MCPurls().forEach { urls.add(it) }
        local.addView(space())
        local.addView(tv("URL del MCP:", 13f, pal.text, true))
        urls.forEach { u -> local.addView(tv(u, 13f, pal.accent).apply { setOnClickListener { copy(u) } }) }
        local.addView(sub(if (Store.bridgeRunning) "Estado: en marcha" else "Estado: apagado"))
        c.addView(local)

        // Tokens
        val tk = card()
        tk.addView(head("IA conectadas (tokens)"))
        val tokens = Store.mcpTokens()
        if (tokens.isEmpty()) tk.addView(sub("Aún no hay IA. Crea un token para cada IA."))
        tokens.forEach { t ->
            val r = col().apply { setPadding(0, dp(6), 0, dp(6)) }
            r.addView(tv("${t.name}  ·  ${if (t.scope == "full") "control total" else "solo lectura"}", 14f, pal.text, true))
            r.addView(sub(t.token.take(10) + "…"))
            r.addView(wrapRow(listOf(
                smallBtn("Copiar token") { copy(t.token) },
                smallBtn("Copiar config", true) { copy(mcpConfig(urls.last(), t.token)) },
                smallBtn("Borrar") { Store.saveMcpTokens(Store.mcpTokens().filter { it.token != t.token }); showTab("ai") }
            )))
            tk.addView(r)
        }
        val nameIn = input("Nombre de la IA (ej. Claude, Gemini, mi agente)")
        tk.addView(nameIn)
        var fullScope = true
        val scopeBtn = smallBtn("Permiso: control total") { }
        scopeBtn.setOnClickListener { fullScope = !fullScope; scopeBtn.text = if (fullScope) "Permiso: control total" else "Permiso: solo lectura" }
        tk.addView(wrapRow(listOf(scopeBtn, smallBtn("Crear token", true) {
            val n = nameIn.text.toString().ifBlank { "IA ${tokens.size + 1}" }
            Store.saveMcpTokens(Store.mcpTokens() + McpToken(n, Store.newToken(), if (fullScope) "full" else "read"))
            showTab("ai")
        })))
        c.addView(tk)

        // Remoto
        val rem = card()
        rem.addView(head("Control remoto (URL MCP del servidor)"))
        rem.addView(sub("Tu servidor en Hostinger expone una URL MCP pública. Tus IA se conectan ahí y el teléfono ejecuta las órdenes en segundos, aunque estés fuera de casa. Los tokens de esa URL se crean en el panel de administración."))
        if (Store.serverUrl.isNotEmpty()) {
            val u = Store.serverUrl + (if (Store.serverUrl.contains("?")) "&" else "?") + "mcp=1"
            rem.addView(tv(u, 13f, pal.accent).apply { setOnClickListener { copy(u) } })
        }
        rem.addView(switchRow("Activar control remoto", if (Store.authToken.isEmpty()) "Primero inicia sesión en Cuenta" else "Sincroniza cada 8 s", Store.remoteEnabled) {
            if (it && !gate(Features.MCP_REMOTE)) { showTab("ai"); return@switchRow }
            if (it && Store.authToken.isEmpty()) { toast("Inicia sesión en Cuenta"); showTab("ai"); return@switchRow }
            Store.remoteEnabled = it; BridgeService.refresh(this)
        })
        rem.addView(smallBtn("Sincronizar ahora") {
            bg { val m = try { Remote.syncOnce(); "Sincronizado" } catch (e: Exception) { "Error: ${e.message}" }; ui { toast(m) } }
        })
        c.addView(rem)

        // Asistente
        val asst = card()
        asst.addView(head("Asistente IA"))
        asst.addView(sub("Pídele cosas como: “bloquea TikTok”, “deja que Chrome pase sin filtro”, “¿qué app manda más anuncios?”. Usa la IA de tu servidor (Gemini), con la clave guardada solo en el servidor."))
        val chat = tv("", 13.5f)
        asst.addView(chat)
        val q = input("Escribe una orden…")
        asst.addView(q)
        asst.addView(btn("Enviar") {
            if (!gate(Features.AI_ASSISTANT)) return@btn
            if (Store.authToken.isEmpty()) { toast("Inicia sesión en Cuenta"); return@btn }
            val text = q.text.toString().trim(); if (text.isEmpty()) return@btn
            q.setText("")
            chat.append("\n🧑 $text\n")
            bg { assistant(text, chat) }
        })
        c.addView(asst)
        return scroll(c)
    }

    private fun MCPurls(): List<String> = McpServer.lanIps(this).map { "http://$it:${Store.mcpPort}/mcp" }

    private fun mcpConfig(url: String, token: String): String = JSONObject().put("mcpServers", JSONObject().put("nexus-firewall",
        JSONObject().put("type", "http").put("url", url).put("headers", JSONObject().put("Authorization", "Bearer $token"))
    )).toString(2)

    private fun assistant(text: String, chat: TextView) {
        try {
            val tools = JSONArray(); Controller.TOOLS.forEach { tools.put(it) }
            val r = Remote.api("ai_command", JSONObject().put("text", text).put("state", Controller.status()).put("tools", tools), 90000)
            val reply = r.optString("reply")
            val actions = r.optJSONArray("actions") ?: JSONArray()
            ui {
                chat.append("🤖 $reply\n")
                if (actions.length() > 0) {
                    val desc = StringBuilder()
                    for (i in 0 until actions.length()) {
                        val a = actions.getJSONObject(i)
                        desc.append("• ${a.optString("tool")} ${a.optJSONObject("args") ?: ""}\n")
                    }
                    AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                        .setTitle("La IA quiere hacer esto").setMessage(desc.toString())
                        .setPositiveButton("Ejecutar") { _, _ ->
                            bg {
                                val sb = StringBuilder()
                                for (i in 0 until actions.length()) {
                                    val a = actions.getJSONObject(i)
                                    val res = Controller.execute(a.optString("tool"), a.optJSONObject("args") ?: JSONObject())
                                    sb.append("✔ ${a.optString("tool")}: ${res.optString("resultado", res.optString("error", "hecho"))}\n")
                                }
                                ui { chat.append(sb.toString()) }
                            }
                        }.setNegativeButton("Cancelar", null).show()
                }
            }
        } catch (e: Exception) { ui { chat.append("⚠ ${e.message}\n") } }
    }

    // ======================= CUENTA / PREMIUM =======================
    private fun accountScreen(): View {
        val c = col()
        val srv = card()
        srv.addView(head("Servidor"))
        val urlIn = input("https://tudominio.com/nexus_firewall_server.php", Store.serverUrl)
        srv.addView(urlIn)
        srv.addView(smallBtn("Guardar servidor") { Store.serverUrl = urlIn.text.toString(); toast("Guardado"); showTab("account") })
        srv.addView(sub(if (Store.serverUrl.isEmpty()) "Sin servidor: todas las funciones están desbloqueadas (modo dueño)." else "Conectado a tu servidor."))
        c.addView(srv)

        if (Store.serverUrl.isEmpty()) return scroll(c)

        if (Store.authToken.isEmpty()) {
            val k = card()
            k.addView(head("Entrar o registrarme"))
            val name = input("Nombre (solo para registro)")
            val email = input("Correo")
            val pass = input("Contraseña", "", true)
            k.addView(name); k.addView(email); k.addView(pass)
            fun go(action: String) {
                bg {
                    try {
                        val r = Remote.api(action, JSONObject().put("email", email.text.toString().trim())
                            .put("password", pass.text.toString()).put("name", name.text.toString().trim()))
                        Store.authToken = r.optString("token"); Store.userEmail = email.text.toString().trim()
                        try { Remote.refreshLicense() } catch (_: Exception) { }
                        ui { toast("Bienvenido"); showTab("account") }
                    } catch (e: Exception) { ui { dialog("Cuenta", e.message ?: "Error") } }
                }
            }
            k.addView(wrapRow(listOf(btn("Entrar") { go("login") }, btn("Registrarme", false) { go("register") })))
            c.addView(k)
            return scroll(c)
        }

        val lic = Store.licenseJson()
        val me = card()
        me.addView(head(if (Store.isPremium()) "👑 Eres Premium" else "Plan Gratis"))
        me.addView(tv(Store.userEmail, 14f))
        val exp = lic.optLong("expires", 0)
        if (Store.isPremium()) {
            me.addView(sub(if (exp == 0L) "Premium sin vencimiento" else "Vence: " +
                SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date(exp * 1000))))
        }
        me.addView(space())
        me.addView(wrapRow(listOf(
            smallBtn("Actualizar estado", true) {
                bg { val m = try { Remote.refreshLicense(); "Actualizado" } catch (e: Exception) { "Error: ${e.message}" }; ui { toast(m); showTab("account") } }
            },
            smallBtn("Cerrar sesión") { Store.authToken = ""; Store.saveLicense(JSONObject()); showTab("account") }
        )))
        c.addView(me)

        val feats = card()
        feats.addView(head("Funciones"))
        val prem = Store.premiumFeatures()
        Features.ALL.forEach { f ->
            val unlocked = Store.allowed(f)
            feats.addView(tv((if (unlocked) "✅ " else "🔒 ") + Features.label(f) + if (f in prem) "  (Premium)" else "  (Gratis)", 13.5f,
                if (unlocked) pal.text else pal.sub))
        }
        c.addView(feats)

        val plans = lic.optJSONArray("plans") ?: JSONArray()
        val pc = card()
        pc.addView(head("Planes Premium"))
        if (plans.length() == 0) pc.addView(sub("El administrador aún no publica planes."))
        for (i in 0 until plans.length()) {
            val p = plans.getJSONObject(i)
            val k = col().apply { setPadding(0, dp(8), 0, dp(8)) }
            k.addView(tv(p.optString("name"), 16f, pal.text, true))
            val days = p.optInt("days")
            k.addView(sub((if (days == 0) "Para siempre" else "$days días") + " · ${p.optString("price")} ${p.optString("currency", "USD")}"))
            if (p.optString("description").isNotEmpty()) k.addView(sub(p.optString("description")))
            k.addView(btn("Pagar con PayPal") {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Remote.payUrl(p.optInt("id")))))
                toast("Al terminar el pago vuelve y toca “Actualizar estado”")
            })
            pc.addView(k)
        }
        c.addView(pc)
        return scroll(c)
    }

    // ======================= AJUSTES =======================
    private fun settingsScreen(): View {
        val c = col()
        val th = card()
        th.addView(head("Temas"))
        th.addView(wrapRow(Themes.ALL.map { p ->
            tv((if (p.id == Store.themeId) "✔ " else "") + p.name + if (p.premium) " 👑" else "", 13f, p.text, true).apply {
                gravity = Gravity.CENTER
                background = rounded(p.bg, 14, 2, p.accent)
                setPadding(dp(8), dp(16), dp(8), dp(16))
                setOnClickListener {
                    if (p.premium && !gate(Features.THEMES)) return@setOnClickListener
                    Store.themeId = p.id
                    val i = Intent(this@MainActivity, MainActivity::class.java).putExtra("tab", "settings")
                    finish(); startActivity(i)
                }
            }
        }))
        c.addView(th)

        val gen = card()
        gen.addView(head("General"))
        gen.addView(switchRow("Iniciar al encender el teléfono", null, Store.autoStart) { Store.autoStart = it })
        gen.addView(smallBtn("VPN siempre activa (ajustes de Android)") { Controller.openVpnSettings(this) })
        gen.addView(space())
        gen.addView(smallBtn("Quitar optimización de batería") {
            try { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) } catch (_: Exception) { }
        })
        c.addView(gen)

        val about = card()
        about.addView(head("Acerca de"))
        about.addView(sub("Nexus Firewall ${BuildConfig.VERSION_NAME}\nFiltro local por DNS: tu navegación no sale a ningún servidor de Nexus. " +
            "El firewall por app funciona con las apps que usan el DNS del sistema (casi todas). Apps que usan DNS cifrado propio pueden saltárselo."))
        c.addView(about)
        return scroll(c)
    }
}
