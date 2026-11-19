package com.nexus.firewall

/** Utilidades para leer y construir paquetes IPv4/UDP/DNS que pasan por el túnel VPN. */
class DnsPacket private constructor(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val dns: ByteArray
) {
    val qname: String
    val qtype: Int
    private val questionEnd: Int

    init {
        var pos = 12
        val sb = StringBuilder()
        var guard = 0
        while (pos < dns.size && guard < 128) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) { pos++; break }
            if (len and 0xC0 != 0) { pos += 2; break }
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..len) {
                if (pos + k < dns.size) sb.append((dns[pos + k].toInt() and 0xFF).toChar())
            }
            pos += len + 1
            guard++
        }
        qname = sb.toString()
        qtype = if (pos + 1 < dns.size) ((dns[pos].toInt() and 0xFF) shl 8) or (dns[pos + 1].toInt() and 0xFF) else 0
        questionEnd = minOf(pos + 4, dns.size)
    }

    /** Respuesta de bloqueo: 0.0.0.0 / :: para A/AAAA y NXDOMAIN para lo demás. */
    fun blockedResponse(): ByteArray {
        val q = dns.copyOfRange(0, questionEnd)
        val rd = q[2].toInt() and 0x01
        val answer: ByteArray? = when (qtype) {
            1 -> byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0)
            28 -> ByteArray(12 + 16).also {
                val h = byteArrayOf(0xC0.toByte(), 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
                System.arraycopy(h, 0, it, 0, 12)
            }
            else -> null
        }
        q[2] = (0x80 or rd).toByte()             // QR=1, RD copiado
        q[3] = if (answer != null) 0x80.toByte() else 0x83.toByte() // RA=1, RCODE 0 ó 3 (NXDOMAIN)
        q[4] = 0; q[5] = 1                       // QDCOUNT
        q[6] = 0; q[7] = (if (answer != null) 1 else 0).toByte() // ANCOUNT
        q[8] = 0; q[9] = 0; q[10] = 0; q[11] = 0
        return if (answer != null) q + answer else q
    }

    /** Envuelve un payload DNS como respuesta IPv4/UDP hacia la app que preguntó. */
    fun wrapResponse(payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val p = ByteArray(total)
        p[0] = 0x45; p[1] = 0
        p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[4] = 0; p[5] = 0; p[6] = 0x40; p[7] = 0
        p[8] = 64; p[9] = 17
        System.arraycopy(dstIp, 0, p, 12, 4)
        System.arraycopy(srcIp, 0, p, 16, 4)
        var sum = 0
        var i = 0
        while (i < 20) { sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF); i += 2 }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val cs = sum.inv() and 0xFFFF
        p[10] = (cs shr 8).toByte(); p[11] = cs.toByte()
        p[20] = (dstPort shr 8).toByte(); p[21] = dstPort.toByte()
        p[22] = (srcPort shr 8).toByte(); p[23] = srcPort.toByte()
        p[24] = (udpLen shr 8).toByte(); p[25] = udpLen.toByte()
        p[26] = 0; p[27] = 0 // checksum UDP opcional en IPv4
        System.arraycopy(payload, 0, p, 28, payload.size)
        return p
    }

    companion object {
        fun parse(buf: ByteArray, len: Int): DnsPacket? {
            if (len < 28) return null
            if ((buf[0].toInt() shr 4) and 0xF != 4) return null
            val ihl = (buf[0].toInt() and 0x0F) * 4
            if (buf[9].toInt() != 17) return null // solo UDP
            val totalLen = minOf(len, ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF))
            if (totalLen < ihl + 8 + 12) return null
            val src = buf.copyOfRange(12, 16)
            val dst = buf.copyOfRange(16, 20)
            val sp = ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl + 1].toInt() and 0xFF)
            val dp = ((buf[ihl + 2].toInt() and 0xFF) shl 8) or (buf[ihl + 3].toInt() and 0xFF)
            if (dp != 53) return null
            val dns = buf.copyOfRange(ihl + 8, totalLen)
            return DnsPacket(src, dst, sp, dp, dns)
        }
    }
}
