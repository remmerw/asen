package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray


internal data class TlsMessageParser(val customExtensionParser: ExtensionParser) {

    suspend fun parseAndProcessHandshakeMessage(
        buffer: Buffer, messageProcessor: MessageProcessor, protectedBy: ProtectionKeysType
    ) {
        // https://tools.ietf.org/html/rfc8446#section-4
        // "      struct {
        //          HandshakeType msg_type;    /* handshake payloadType */
        //          uint24 length;             /* remaining bytes in message */
        //          ...
        //      } Handshake;"

        val data = buffer.copy().readByteArray()

        val messageType = buffer.readByte().toInt()


        val type: HandshakeType = HandshakeType.get(messageType)
            ?: throw HandshakeFailureAlert("Invalid/unsupported message payloadType ($messageType)")

        when (type) {
            HandshakeType.CLIENT_HELLO -> {
                val ch: ClientHello = ClientHello.parse(
                    buffer,
                    customExtensionParser,
                    data
                )
                messageProcessor.received(ch)
            }

            HandshakeType.SERVER_HELLO -> {
                val sh: ServerHello = ServerHello.parse(buffer, data)
                messageProcessor.received(sh)
            }

            HandshakeType.ENCRYPTED_EXTENSIONS -> {
                val ee: EncryptedExtensions = EncryptedExtensions.parse(
                    buffer,
                    customExtensionParser,
                    data
                )
                messageProcessor.received(ee, protectedBy)
            }

            HandshakeType.CERTIFICATE -> {
                val cm: CertificateMessage = CertificateMessage.parse(buffer, data)
                messageProcessor.received(cm, protectedBy)
            }

            HandshakeType.CERTIFICATE_REQUEST -> {
                val cr: CertificateRequestMessage =
                    CertificateRequestMessage.parse(buffer, data)
                messageProcessor.received(cr, protectedBy)
            }

            HandshakeType.CERTIFICATE_VERIFY -> {
                val cv: CertificateVerifyMessage = CertificateVerifyMessage.parse(buffer, data)
                messageProcessor.received(cv, protectedBy)
            }

            HandshakeType.FINISHED -> {
                val fm: FinishedMessage = FinishedMessage.parse(buffer, data)
                messageProcessor.received(fm, protectedBy)
            }

            else -> throw HandshakeFailureAlert(
                "Invalid/unsupported " +
                        "message type (" + messageType + ")"
            )
        }
    }
}
