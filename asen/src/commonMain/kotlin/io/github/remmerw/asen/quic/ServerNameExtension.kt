package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * TLS server name extension: RFC 6066
 * [...](https://tools.ietf.org/html/rfc6066#section-3)
 */
internal data class ServerNameExtension(val serverName: String?) : Extension {
    override fun getBytes(): ByteArray {
        val hostnameLength = serverName!!.length.toShort()
        val extensionLength = (hostnameLength + 2 + 1 + 2).toShort()

        val buffer = Buffer()

        buffer.writeShort(ExtensionType.SERVER_NAME.value)
        buffer.writeShort(extensionLength) // Extension data length (in bytes)

        // https://tools.ietf.org/html/rfc6066#section-3
        buffer.writeShort((hostnameLength + 1 + 2).toShort()) // Length of server_name_list
        buffer.writeByte(0x00.toByte()) // list entry is payloadType 0x00 "DNS hostname"
        buffer.writeShort(hostnameLength) // Length of hostname
        buffer.write(serverName.encodeToByteArray())
        require(buffer.size.toInt() == 4 + extensionLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.SERVER_NAME
    }

    companion object {
        fun parse(buffer: Buffer, extensionLength: Int): ServerNameExtension {
            val serverName: String?
            val extensionDataLength =
                validateExtensionHeader(buffer, extensionLength, 0)
            if (extensionDataLength > 0) {
                if (extensionDataLength < 2) {
                    throw DecodeErrorException("incorrect extension length")
                }
                val serverNameListLength = buffer.readShort().toInt()
                if (extensionDataLength != serverNameListLength + 2) {
                    throw DecodeErrorException("inconsistent length")
                }
                serverName = parseServerName(buffer)
            } else {
                // https://tools.ietf.org/html/rfc6066#section-3
                // " A server that receives a client hello containing the "server_name" extension (...). In this event,
                // the server SHALL include an extension of payloadType "server_name" in the (extended) server hello.
                // The "extension_data" field of this extension SHALL be empty."
                serverName = null
            }
            return ServerNameExtension(serverName)
        }


        private fun parseServerName(buffer: Buffer): String {
            val nameType = buffer.readByte().toInt()
            if (nameType == 0) { // host_name
                val hostNameLength = buffer.readShort().toInt() and 0xffff
                if (hostNameLength > buffer.size) {
                    throw DecodeErrorException("extension underflow")
                }
                val hostNameBytes = buffer.readByteArray(hostNameLength)
                // "The hostname is represented as a byte string using ASCII encoding without a trailing dot. "
                return hostNameBytes.decodeToString()
            }
            // unsupported payloadType, RFC 6066 only defines hostname
            throw DecodeErrorException("invalid NameType")
        }
    }
}
