package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * TLS Early Data Indication extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.10)
 */
internal data class EarlyDataExtension(val maxEarlyDataSize: Long) : Extension {
    override fun getBytes(): ByteArray {
        val extensionDataLength = if (maxEarlyDataSize == -1L) 0 else 4
        val buffer = Buffer()
        buffer.writeShort(ExtensionType.EARLY_DATA.value)
        buffer.writeShort(extensionDataLength.toShort())
        if (maxEarlyDataSize > -1) {
            buffer.writeInt(maxEarlyDataSize.toInt())
        }
        require(buffer.size.toInt() == 4 + extensionDataLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.EARLY_DATA
    }

    companion object {

        fun parse(
            buffer: Buffer,
            extensionLength: Int,
            context: HandshakeType
        ): EarlyDataExtension {
            val extensionDataLength =
                validateExtensionHeader(
                    buffer,
                    extensionLength,
                    0
                )
            var maxEarlyDataSize: Long = -1
            // Only when used in New Session Ticket (message), the EarlyDataIndication value is non-empty.
            if (context == HandshakeType.NEW_SESSION_TICKET) {
                if (extensionDataLength == 4) {
                    maxEarlyDataSize = buffer.readInt().toLong() and 0xffffffffL
                } else {
                    throw DecodeErrorException("invalid extension data length")
                }
            } else if (extensionDataLength != 0) {
                throw DecodeErrorException("invalid extension data length")
            }
            return EarlyDataExtension(maxEarlyDataSize)
        }
    }
}
