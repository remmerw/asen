package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

@Suppress("ArrayInDataClass")
internal data class UnknownExtension(val type: Int, val data: ByteArray) : Extension {
    override fun getBytes(): ByteArray {
        return ByteArray(0)
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.UNKNOWN
    }

    companion object {

        fun parse(buffer: Buffer, extensionType: Int, extensionLength: Int): UnknownExtension {

            if (buffer.size < extensionLength) {
                throw DecodeErrorException("Invalid extension length")
            }
            val data = buffer.readByteArray(extensionLength)

            return UnknownExtension(extensionType, data)
        }
    }
}
