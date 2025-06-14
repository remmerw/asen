package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

// https://tools.ietf.org/html/rfc8446#section-4.4.3
// "Certificate Verify
//   This message is used to provide explicit proof that an endpoint possesses the private key corresponding to its certificate.  The
//   CertificateVerify message also provides integrity for the handshake up to this point.  Servers MUST send this message when authenticating
//   via a certificate.  Clients MUST send this message whenever authenticating via a certificate (i.e., when the Certificate message
//   is non-empty). "

@Suppress("ArrayInDataClass")
internal data class CertificateVerifyMessage(
    val signatureScheme: SignatureScheme,
    private val signature: ByteArray,
    override val bytes: ByteArray
) : HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.CERTIFICATE_VERIFY

    companion object {
        private const val MINIMUM_MESSAGE_SIZE = 1 + 3 + 2 + 2 + 1

        fun createCertificateVerifyMessage(
            signatureScheme: SignatureScheme,
            signature: ByteArray
        ): CertificateVerifyMessage {
            val signatureLength = signature.size
            val buffer = Buffer()

            buffer.writeInt((HandshakeType.CERTIFICATE_VERIFY.value.toInt() shl 24) or (2 + 2 + signatureLength))
            buffer.writeShort(signatureScheme.value)
            buffer.writeShort(signatureLength.toShort())
            buffer.write(signature)
            require(buffer.size.toInt() == 4 + 2 + 2 + signatureLength)
            return CertificateVerifyMessage(signatureScheme, signature, buffer.readByteArray())
        }

        fun parse(buffer: Buffer, data: ByteArray): CertificateVerifyMessage {

            parseHandshakeHeader(
                buffer,
                MINIMUM_MESSAGE_SIZE
            )

            try {
                val signatureSchemeValue = buffer.readShort()
                val signatureScheme: SignatureScheme =
                    SignatureScheme.get(signatureSchemeValue)

                val signatureLength = buffer.readShort().toInt() and 0xffff
                val signature = buffer.readByteArray(signatureLength)

                return CertificateVerifyMessage(signatureScheme, signature, data)
            } catch (throwable: Throwable) {
                throw DecodeErrorException("message " + throwable.message)
            }
        }
    }

}
