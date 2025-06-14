package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

// https://tools.ietf.org/html/rfc8446#section-4.3.2
@Suppress("ArrayInDataClass")
internal data class CertificateRequestMessage(
    val certificateRequestContext: ByteArray,
    val extensions: List<Extension>,
    override val bytes: ByteArray
) : HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.CERTIFICATE_REQUEST

    companion object {
        private const val MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 2


        fun parse(buffer: Buffer, data: ByteArray): CertificateRequestMessage {

            parseHandshakeHeader(
                buffer,
                MINIMUM_MESSAGE_SIZE
            )

            val contextLength = buffer.readByte().toInt()
            val certificateRequestContext = buffer.readByteArray(contextLength)

            val extensions = parseExtensions(
                buffer, HandshakeType.CERTIFICATE_REQUEST, null
            )


            return CertificateRequestMessage(certificateRequestContext, extensions, data)
        }
    }

}
