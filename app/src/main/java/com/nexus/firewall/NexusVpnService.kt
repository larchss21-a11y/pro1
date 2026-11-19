package com.nexus.firewall

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class NexusVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.nexus.firewall.START"
        const val ACTION_STOP = "com.nexus.firewall.STOP"
        const val ACTION_RESTART = "com.nexus.firewall.RESTART"
        private const val CHANNEL = "nexus_vpn"
        private const val NOTIF_ID = 1001

        fun start(ctx: Context) = send(ctx, ACTION_START)
        fun stop(ctx: Context) = send(ctx, ACTION_STOP)
        fun restart(ctx: Context) { if (Store.vpnRunning) send(ctx, ACTION_RESTART) }

        private fun send(ctx: Context, action: String) {
            val i = Intent(ctx, NexusVpnService::class.java).setAction(action)
            if (action == ACTION_STOP) ctx.startService(i) else ctx.startForegroundService(i)
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var running = false
    private var pool: ExecutorService? = null
    private val uidCache = ConcurrentHashMap<Int, String>()
    private var out: FileOutputStream? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { Store.wantVpn = false; shutdown(); stopSelf(); return START_NOT_STICKY }
            ACTION_RESTART -> { goForeground(); shutdown(); establish() }
            else -> { goForeground(); if (!running) establish() }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Store.wantVpn = false
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun goForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Nexus Firewall", NotificationManager.IMPORTANCE_LOW))
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n: Notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Nexus Firewall activo")
            .setContentText("Bloqueados: ${Store.totalBlocked.get()} de ${Store.totalQueries.get()} consultas")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun establish() {
        try {
            val b = Builder()
                .setSession("Nexus Firewall")
                .addAddress(Config.VPN_ADDRESS, 32)
                .addDnsServer(Config.FAKE_DNS)
                .addRoute(Config.FAKE_DNS, 32)
                .setMtu(1500)
            // Nexus mismo nunca pasa por el filtro (descargas de listas, servidor, MCP).
            try { b.addDisallowedApplication(packageName) } catch (_: Exception) { }
            // Apps que tú decides que pasen sin filtro.
            if (Store.allowed(Features.BYPASS_APPS)) {
                for (p in Store.bypassApps) {
                    try { b.addDisallowedApplication(p) } catch (_: Exception) { }
                }
            }
            if (Build.VERSION.SDK_INT >= 29) {
                b.setBlocking(true)
                b.setMetered(false)
            }
            val pfd = b.establish() ?: run { Store.vpnRunning = false; stopSelf(); return }
            tun = pfd
            out = FileOutputStream(pfd.fileDescriptor)
            running = true
            Store.vpnRunning = true
            Store.wantVpn = true
            pool = Executors.newFixedThreadPool(12)
            worker = Thread({ loop(pfd) }, "nexus-tun").also { it.start() }
        } catch (e: Exception) {
            Store.vpnRunning = false
            stopSelf()
        }
    }

    private fun shutdown() {
        running = false
        Store.vpnRunning = false
        Store.saveStats()
        try { worker?.interrupt() } catch (_: Exception) { }
        try { pool?.shutdownNow() } catch (_: Exception) { }
        try { tun?.close() } catch (_: Exception) { }
        tun = null; worker = null; pool = null; out = null
    }

    private fun loop(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val buf = ByteArray(32767)
        var lastNotif = 0L
        while (running) {
            val n = try { input.read(buf) } catch (e: Exception) {
                if (!running) break
                try { Thread.sleep(15) } catch (_: InterruptedException) { break }
                continue
            }
            if (n <= 0) {
                try { Thread.sleep(10) } catch (_: InterruptedException) { break }
                continue
            }
            val pkt = DnsPacket.parse(buf, n) ?: continue
            val p = pool ?: continue
            try { p.execute { handle(pkt) } } catch (_: Exception) { }
            val now = System.currentTimeMillis()
            if (now - lastNotif > 30000) {
                lastNotif = now
                Store.saveStats()
                try { goForeground() } catch (_: Exception) { }
            }
        }
    }

    private fun ownerPackage(pkt: DnsPacket): String {
        if (Build.VERSION.SDK_INT < 29) return ""
        return try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val uid = cm.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(pkt.srcIp), pkt.srcPort),
                InetSocketAddress(InetAddress.getByAddress(pkt.dstIp), pkt.dstPort)
            )
            if (uid < 0) return ""
            uidCache[uid] ?: run {
                val name = packageManager.getPackagesForUid(uid)?.firstOrNull() ?: "uid:$uid"
                uidCache[uid] = name
                name
            }
        } catch (e: Exception) { "" }
    }

    private fun handle(pkt: DnsPacket) {
        val domain = pkt.qname
        if (domain.isEmpty()) return
        val pkg = ownerPackage(pkt)
        val v = Engine.decide(domain, pkg)
        Store.totalQueries.incrementAndGet()
        if (v.block) Store.totalBlocked.incrementAndGet()
        Store.addLog(LogEntry(System.currentTimeMillis(), domain.lowercase(), pkg, v.block, v.reason))
        val response: ByteArray = if (v.block) {
            pkt.blockedResponse()
        } else {
            forward(pkt.dns) ?: return
        }
        writeOut(pkt.wrapResponse(response))
    }

    private fun forward(query: ByteArray): ByteArray? {
        var sock: DatagramSocket? = null
        return try {
            sock = DatagramSocket()
            protect(sock)
            sock.soTimeout = 5000
            val addr = InetAddress.getByName(Store.upstreamDns)
            sock.send(DatagramPacket(query, query.size, addr, 53))
            val rb = ByteArray(4096)
            val rp = DatagramPacket(rb, rb.size)
            sock.receive(rp)
            rb.copyOf(rp.length)
        } catch (e: Exception) {
            null
        } finally {
            try { sock?.close() } catch (_: Exception) { }
        }
    }

    private fun writeOut(bytes: ByteArray) {
        val o = out ?: return
        synchronized(this) {
            try { o.write(bytes) } catch (_: Exception) { }
        }
    }
}
