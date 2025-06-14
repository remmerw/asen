package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * TLS Pre-Shared Key Extension, ServerHello variant.
 * see [...](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
 */
internal data class ServerPreSharedKeyExtension(val selectedIdentity: Int) : PreSharedKeyExtension {
    override fun getBytes(): ByteArray {
        val buffer = Buffer()
        buffer.writeShort(ExtensionType.PRE_SHARED_KEY.value)
        buffer.writeShort(0x02.toShort())
        buffer.writeShort(selectedIdentity.toShort())
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.SERVER_PRE_SHARED_KEY
    }

    companion object {

        fun parse(buffer: Buffer, extensionLength: Int): ServerPreSharedKeyExtension {
            validateExtensionHeader(buffer, extensionLength, 2)
            return ServerPreSharedKeyExtension(buffer.readShort().toInt())
        }
    }
}
