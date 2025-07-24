package io.github.remmerw.asen.core

import io.github.remmerw.asen.IP4
import io.github.remmerw.asen.IP6
import io.github.remmerw.asen.UDP
import io.github.remmerw.asen.parsePeerId
import io.github.remmerw.borr.PeerId
import io.github.remmerw.borr.decode58
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.io.writeUShort
import kotlin.experimental.or


internal fun holder(address: ByteArray): Int {
    var holder: Int = address[3].toInt() and 0xFF
    holder = holder or ((address[2].toInt() shl 8) and 0xFF00)
    holder = holder or ((address[1].toInt() shl 16) and 0xFF0000)
    holder = holder or ((address[0].toInt() shl 24) and -0x1000000)
    return holder
}

internal fun encodeProtocol(code: Int, out: Buffer) {
    val variant = ByteArray((32 - code.countLeadingZeroBits() + 6) / 7)
    putVariant(variant, code.toLong())
    out.write(variant)
}

internal fun encodePart(port: UShort, buffer: Buffer) {
    buffer.writeUShort(port)
}

internal fun encodePart(address: ByteArray, buffer: Buffer) {
    buffer.write(address)
}

fun encoded(address: ByteArray, port: UShort): ByteArray {
    Buffer().use { buffer ->
        if (address.size == 4) { // IP4
            encodeProtocol(IP4, buffer)
        } else {
            encodeProtocol(IP6, buffer)
        }
        encodePart(address, buffer)
        encodeProtocol(UDP, buffer)
        encodePart(port, buffer)
        return buffer.readByteArray()
    }
}

private fun putVariant(buf: ByteArray, value: Long) {
    var x = value
    var i = 0
    while (x >= 0x80) {
        buf[i] = (x or 0x80L).toByte()
        x = x shr 7
        i++
    }
    buf[i] = x.toByte()
}

fun isLanAddress(address: ByteArray): Boolean {
    return isAnyLocalAddress(address)
            || isLinkLocalAddress(address)
            || isLoopbackAddress(address)
            || isSiteLocalAddress(address)
}

fun isAnyLocalAddress(address: ByteArray): Boolean {
    if (address.size == 16) {
        var test: Byte = 0x00
        for (i in 0..15) {
            test = test or address[i]
        }
        return (test.toInt() == 0x00)
    } else {
        return holder(address) == 0
    }
}

fun isLoopbackAddress(address: ByteArray): Boolean {
    if (address.size == 16) {
        var test: Byte = 0x00
        for (i in 0..14) {
            test = test or address[i]
        }
        return (test.toInt() == 0x00) && (address[15].toInt() == 0x01)
    } else {
        return address[0].toInt() == 127
    }
}

fun isLinkLocalAddress(address: ByteArray): Boolean {

    if (address.size == 16) {
        return ((address[0].toInt() and 0xff) == 0xfe
                && (address[1].toInt() and 0xc0) == 0x80)
    } else {


        // link-local unicast in IPv4 (169.254.0.0/16)
        // defined in "Documenting Special Use IPv4 Address Blocks
        // that have been Registered with IANA" by Bill Manning
        // draft-manning-dsua-06.txt
        val address: Int = holder(address)
        return (((address ushr 24) and 0xFF) == 169)
                && (((address ushr 16) and 0xFF) == 254)
    }
}


fun isSiteLocalAddress(address: ByteArray): Boolean {
    if (address.size == 16) {
        return ((address[0].toInt() and 0xff) == 0xfe
                && (address[1].toInt() and 0xc0) == 0xc0)
    } else {
        // refer to RFC 1918
        // 10/8 prefix
        // 172.16/12 prefix
        // 192.168/16 prefix
        val address: Int = holder(address)
        return (((address ushr 24) and 0xFF) == 10)
                || ((((address ushr 24) and 0xFF) == 172)
                && (((address ushr 16) and 0xF0) == 16))
                || ((((address ushr 24) and 0xFF) == 192)
                && (((address ushr 16) and 0xFF) == 168))
    }
}


private const val SHA2_256 = 0x12
internal fun decodePeerIdByName(name: String): PeerId {
    val raw = decode58(name)
    if (name.startsWith("1")) {
        val peerId = parsePeerId(raw)
        if (peerId != null) {
            return peerId
        }
    }

    if (name.startsWith("Qm")) {  // TODO FUTURE [medium] only support Multihash.ID)
        val buffer = Buffer()
        buffer.write(raw)

        val type = readUnsignedVariant(buffer)
        val len = readUnsignedVariant(buffer)

        val hash = buffer.readByteArray(len)

        require(buffer.exhausted()) { "still data available" }
        require(type == SHA2_256) { "invalid type" }

        return PeerId(hash)
    }

    throw IllegalStateException("not supported multihash")
}

