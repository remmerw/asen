package io.github.remmerw.asen.quic

import kotlinx.io.Buffer

// https://tools.ietf.org/html/rfc8446#section-4.3.1
@Suppress("ArrayInDataClass")
internal data class EncryptedExtensions(
    val extensions: List<Extension>,
    override val bytes: ByteArray
) :
    HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.ENCRYPTED_EXTENSIONS


    companion object {
        private const val MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2


        fun parse(
            buffer: Buffer,
            customExtensionParser: ExtensionParser?,
            data: ByteArray
        ): EncryptedExtensions {
            if (buffer.size < MINIMAL_MESSAGE_LENGTH) {
                throw DecodeErrorException("Message too short")
            }

            val msgLength = ((buffer.readByte().toInt() and 0xff) shl 16) or ((buffer.readByte()
                .toInt() and 0xff) shl 8) or (buffer.readByte().toInt() and 0xff)
            if (buffer.size < msgLength || msgLength < 2) {
                throw DecodeErrorException("Incorrect message length")
            }

            val extensions = parseExtensions(
                buffer,
                HandshakeType.SERVER_HELLO, customExtensionParser
            )

            return EncryptedExtensions(extensions, data)
        }
    }
}
