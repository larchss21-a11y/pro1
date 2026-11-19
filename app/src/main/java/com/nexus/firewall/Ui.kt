package com.nexus.firewall

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

data class Palette(
    val id: String, val name: String,
    val bg: Int, val card: Int, val accent: Int, val text: Int, val sub: Int,
    val premium: Boolean
)

object Themes {
    private fun c(s: String) = Color.parseColor(s)
    val ALL = listOf(
        Palette("rojo", "Nexus Rojo y Negro", c("#0A0A0A"), c("#171717"), c("#E10600"), c("#FFFFFF"), c("#A8A8A8"), false),
        Palette("neon", "Rojo Neón", c("#000000"), c("#120406"), c("#FF1744"), c("#FFEDEF"), c("#C98A93"), false),
        Palette("sangre", "Sangre Oscura", c("#0D0203"), c("#1E0709"), c("#B71C1C"), c("#F5E6E6"), c("#B08A8A"), true),
        Palette("cyber", "Cyber Azul", c("#050A12"), c("#0D1726"), c("#00B0FF"), c("#E6F4FF"), c("#8AA4BF"), true),
        Palette("matrix", "Matrix Verde", c("#020802"), c("#0B170B"), c("#00E676"), c("#E6FFE9"), c("#86B38D"), true),
        Palette("morado", "Morado Nocturno", c("#0B0612"), c("#170F24"), c("#B388FF"), c("#F1EAFF"), c("#A596BF"), true),
        Palette("oro", "Oro y Negro", c("#0A0802"), c("#18140A"), c("#FFC400"), c("#FFF8E1"), c("#BFAE7A"), true)
    )

    fun current(): Palette {
        val p = ALL.firstOrNull { it.id == Store.themeId } ?: ALL[0]
        return if (p.premium && !Store.allowed(Features.THEMES)) ALL[0] else p
    }
}

/** Pequeño kit para construir la interfaz por código con el tema activo. */
open class UiActivity : Activity() {
    val pal: Palette get() = Themes.current()

    fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
    fun dpf(v: Float): Float = v * resources.displayMetrics.density

    fun isWide(): Boolean = resources.configuration.screenWidthDp >= 600

    fun rounded(color: Int, radius: Int = 14, stroke: Int = 0, strokeColor: Int = 0): GradientDrawable =
        GradientDrawable().apply {
            setColor(color); cornerRadius = dpf(radius.toFloat())
            if (stroke > 0) setStroke(dp(stroke), strokeColor)
        }

    fun tv(text: CharSequence, size: Float = 14f, color: Int = pal.text, bold: Boolean = false): TextView =
        TextView(this).apply {
            this.text = text; textSize = size; setTextColor(color)
            if (bold) typeface = Typeface.DEFAULT_BOLD
        }

    fun head(text: String): TextView = tv(text, 18f, pal.accent, true).apply { setPadding(0, dp(8), 0, dp(6)) }

    fun sub(text: CharSequence): TextView = tv(text, 12.5f, pal.sub)

    fun btn(text: String, primary: Boolean = true, onClick: () -> Unit): TextView = TextView(this).apply {
        this.text = text
        textSize = 14f
        typeface = Typeface.DEFAULT_BOLD
        gravity = Gravity.CENTER
        setTextColor(if (primary) Color.WHITE else pal.accent)
        background = if (primary) rounded(pal.accent, 12) else rounded(Color.TRANSPARENT, 12, 1, pal.accent)
        setPadding(dp(14), dp(10), dp(14), dp(10))
        isClickable = true
        setOnClickListener { onClick() }
    }

    fun smallBtn(text: String, primary: Boolean = false, onClick: () -> Unit): TextView =
        btn(text, primary, onClick).apply { textSize = 12f; setPadding(dp(10), dp(6), dp(10), dp(6)) }

    fun col(): LinearLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

    fun row(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

    fun card(): LinearLayout = col().apply {
        background = rounded(pal.card, 16)
        setPadding(dp(14), dp(12), dp(14), dp(12))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            .apply { setMargins(0, dp(6), 0, dp(6)) }
    }

    fun input(hint: String, value: String = "", password: Boolean = false): EditText = EditText(this).apply {
        this.hint = hint
        setText(value)
        setTextColor(pal.text)
        setHintTextColor(pal.sub)
        textSize = 14f
        background = rounded(pal.bg, 10, 1, pal.sub)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        isSingleLine = true
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            .apply { setMargins(0, dp(4), 0, dp(4)) }
    }

    fun switchRow(label: String, subText: String?, checked: Boolean, onChange: (Boolean) -> Unit): View {
        val r = row().apply { setPadding(0, dp(6), 0, dp(6)) }
        val texts = col()
        texts.addView(tv(label, 15f, pal.text, true))
        if (subText != null) texts.addView(sub(subText))
        r.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val sw = Switch(this)
        sw.isChecked = checked
        val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
        sw.thumbTintList = ColorStateList(states, intArrayOf(pal.accent, pal.sub))
        sw.trackTintList = ColorStateList(states, intArrayOf(adjustAlpha(pal.accent, 0.5f), adjustAlpha(pal.sub, 0.3f)))
        sw.setOnCheckedChangeListener { _, v -> onChange(v) }
        r.addView(sw)
        return r
    }

    fun adjustAlpha(color: Int, f: Float): Int =
        Color.argb((Color.alpha(color) * f).toInt(), Color.red(color), Color.green(color), Color.blue(color))

    fun space(h: Int = 8): View = View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(h)) }

    fun scroll(content: LinearLayout): ScrollView = ScrollView(this).apply {
        isFillViewport = true
        val side = if (isWide()) dp(48) else dp(12)
        content.setPadding(side, dp(8), side, dp(24))
        addView(content)
    }

    fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    fun copy(text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("nexus", text))
        toast("Copiado")
    }

    fun ui(block: () -> Unit) = runOnUiThread { block() }
    fun bg(block: () -> Unit) = Thread { block() }.start()

    fun dialog(title: String, msg: String) {
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(title).setMessage(msg).setPositiveButton("OK", null).show()
    }

    fun wrapRow(views: List<View>): LinearLayout {
        // Fila que se parte en varias líneas en pantallas pequeñas
        val container = col()
        val perRow = if (isWide()) 4 else 2
        var r: LinearLayout? = null
        views.forEachIndexed { i, v ->
            if (i % perRow == 0) { val nr = row(); r = nr; container.addView(nr) }
            val lp = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(dp(3), dp(3), dp(3), dp(3)) }
            r?.addView(v, lp)
        }
        val rem = views.size % perRow
        if (rem != 0) repeat(perRow - rem) { r?.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f)) }
        return container
    }
}
