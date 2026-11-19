package com.nexus.firewall

import android.app.Activity
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.UserManager
import android.widget.Toast

/**
 * Clonador: crea un "espacio clonado" (perfil de trabajo de Android) del que Nexus es dueño.
 * Dentro de ese espacio se pueden instalar copias de tus apps con otra cuenta/sesión.
 */
object Cloner {
    const val ACTION_CLONE = "com.nexus.firewall.action.CLONE"
    const val EXTRA_PKG = "pkg"
    const val EXTRA_MODE = "mode" // clone | hide | wipe

    fun admin(ctx: Context) = ComponentName(ctx, NexusAdminReceiver::class.java)

    fun dpm(ctx: Context) = ctx.getSystemService(DevicePolicyManager::class.java)

    /** ¿Esta instancia de Nexus corre dentro del espacio clonado? */
    fun insideProfile(ctx: Context): Boolean = dpm(ctx).isProfileOwnerApp(ctx.packageName)

    /** ¿Existe ya el espacio clonado? */
    fun profileExists(ctx: Context): Boolean {
        val um = ctx.getSystemService(UserManager::class.java)
        return um.userProfiles.size > 1
    }

    fun provisioningIntent(ctx: Context): Intent? {
        val i = Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)
            .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME, admin(ctx))
            .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, true)
        return if (i.resolveActivity(ctx.packageManager) != null) i else null
    }

    /** Envía la orden al espacio clonado (cruza de perfil personal a perfil de trabajo). */
    fun sendToProfile(ctx: Activity, pkg: String, mode: String): Boolean {
        return try {
            val i = Intent(ACTION_CLONE).putExtra(EXTRA_PKG, pkg).putExtra(EXTRA_MODE, mode)
            val targets = ctx.packageManager.queryIntentActivities(i, 0)
            // Busca la ruta que cruza al perfil (la que no es nuestra propia actividad local)
            val cross = targets.firstOrNull { it.activityInfo.packageName != ctx.packageName }
            if (cross != null) {
                i.setClassName(cross.activityInfo.packageName, cross.activityInfo.name)
            }
            ctx.startActivity(i)
            true
        } catch (e: Exception) {
            Toast.makeText(ctx, "No se pudo: ${e.message}", Toast.LENGTH_LONG).show()
            false
        }
    }

    /** Configuración inicial dentro del perfil recién creado. */
    fun setupProfile(ctx: Context) {
        val d = dpm(ctx)
        val a = admin(ctx)
        try { d.setProfileName(a, "Nexus Clones") } catch (_: Exception) { }
        try {
            val f = IntentFilter(ACTION_CLONE).apply { addCategory(Intent.CATEGORY_DEFAULT) }
            d.addCrossProfileIntentFilter(a, f, DevicePolicyManager.FLAG_PARENT_CAN_ACCESS_MANAGED)
        } catch (_: Exception) { }
        try { d.setProfileEnabled(a) } catch (_: Exception) { }
    }

    /** Ejecutado DENTRO del perfil: instala/oculta la copia. */
    fun applyInProfile(ctx: Context, pkg: String, mode: String): String {
        val d = dpm(ctx)
        val a = admin(ctx)
        return try {
            when (mode) {
                "wipe" -> { d.wipeData(0); "Espacio clonado eliminado" }
                "hide" -> { d.setApplicationHidden(a, pkg, true); "Clon de $pkg ocultado" }
                else -> {
                    d.setApplicationHidden(a, pkg, false)
                    val ok = if (Build.VERSION.SDK_INT >= 28) d.installExistingPackage(a, pkg) else {
                        d.enableSystemApp(a, pkg); true
                    }
                    if (ok) "Clon creado: $pkg (búscalo con el maletín)" else "Android no permitió clonar $pkg"
                }
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }
}

class NexusAdminReceiver : DeviceAdminReceiver() {
    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        Cloner.setupProfile(context)
    }
}

/** Corre dentro del espacio clonado cuando el perfil personal pide clonar. */
class CloneActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pkg = intent.getStringExtra(Cloner.EXTRA_PKG) ?: ""
        val mode = intent.getStringExtra(Cloner.EXTRA_MODE) ?: "clone"
        val msg = if (!Cloner.insideProfile(this)) {
            "Primero crea el espacio clonado"
        } else if (pkg.isEmpty() && mode != "wipe") {
            "Falta la app"
        } else {
            Cloner.applyInProfile(this, pkg, mode)
        }
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        finish()
    }
}

class ProvisioningDoneActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Cloner.setupProfile(this)
        setResult(RESULT_OK)
        finish()
    }
}

class GetProvisioningModeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val r = Intent()
        if (Build.VERSION.SDK_INT >= 31) {
            r.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_MODE, DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE)
        }
        setResult(RESULT_OK, r)
        finish()
    }
}

class PolicyComplianceActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_OK)
        finish()
    }
}
