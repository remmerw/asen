package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * The TLS supported versions extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.1)
 */
internal data class SupportedVersionsExtension(
    val handshakeType: HandshakeType,
    val tlsVersion: Short
) : Extension {
    override fun getBytes(): ByteArray {
        val buffer = Buffer()

        buffer.writeShort(ExtensionType.SUPPORTED_VERSIONS.value)

        // TLS 1.3
        if (handshakeType == HandshakeType.CLIENT_HELLO) {
            buffer.writeShort(3.toShort()) // Extension data length (in bytes)
            buffer.writeByte(0x02.toByte()) // TLS versions bytes
        } else {
            buffer.writeShort(2.toShort()) // Extension data length (in bytes)
        }
        buffer.write(byteArrayOf(0x03.toByte(), 0x04.toByte())) // TLS 1.3

        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.SUPPORTED_VERSIONS
    }

    companion object {
        private const val TLS13 = 0x0304.toShort()

        fun createSupportedVersionsExtension(handshakeType: HandshakeType): SupportedVersionsExtension {
            return SupportedVersionsExtension(handshakeType, TLS13)
        }


        fun parse(
            buffer: Buffer, extensionLength: Int, handshakeType: HandshakeType
        ): SupportedVersionsExtension {
            var tlsVersion: Short = 0
            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 2
            )

            if (handshakeType == HandshakeType.CLIENT_HELLO) {
                val versionsLength = buffer.readByte().toInt() and 0xff
                if (versionsLength % 2 == 0 && extensionDataLength == versionsLength + 1) {
                    var i = 0
                    while (i < versionsLength) {
                        val version = buffer.readShort()
                        // This implementation only supports TLS 1.3, so search for that version.
                        if (version == TLS13) {
                            tlsVersion = version
                        }
                        i += 2
                    }
                } else {
                    throw DecodeErrorException("invalid versions length")
                }
            } else if (handshakeType == HandshakeType.SERVER_HELLO) {
                if (extensionDataLength != 2) {
                    throw DecodeErrorException("Incorrect extension length")
                }
                tlsVersion = buffer.readShort()
            } else {
                throw IllegalArgumentException()
            }
            // 0x0304 is TLS1.3
            if (tlsVersion != TLS13) throw UnsupportedExtensionAlert("TLS1.3 not supported")
            return SupportedVersionsExtension(handshakeType, TLS13)
        }
    }
}
