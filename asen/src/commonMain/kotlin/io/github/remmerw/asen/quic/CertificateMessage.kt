package io.github.remmerw.asen.quic


import kotlinx.io.Buffer
import kotlinx.io.readByteArray

// https://tools.ietf.org/html/rfc8446#section-4.4.2
@Suppress("ArrayInDataClass")
internal data class CertificateMessage(
    val requestContext: ByteArray,
    val certificateChain: Array<X509Certificate>,
    override val bytes: ByteArray
) : HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.CERTIFICATE


    val endEntityCertificate: X509Certificate
        // https://tools.ietf.org/html/rfc8446#section-4.4.2
        get() = certificateChain[0]

    companion object {
        private const val MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 3 + 3 + 2

        fun createCertificateMessage(certificate: Certificate): CertificateMessage {
            val requestContext = ByteArray(0)
            return CertificateMessage(requestContext, arrayOf(), serialize(certificate))
        }


        fun parse(buffer: Buffer, data: ByteArray): CertificateMessage {
            parseHandshakeHeader(buffer, MINIMUM_MESSAGE_SIZE)

            try {
                val requestContext: ByteArray
                val certificateRequestContextSize = buffer.readByte().toInt() and 0xff
                requestContext = if (certificateRequestContextSize > 0) {
                    buffer.readByteArray(certificateRequestContextSize)
                } else {
                    ByteArray(0)
                }
                val certificateChain = parseCertificateEntries(buffer)


                return CertificateMessage(
                    requestContext,
                    certificateChain.toTypedArray(), data
                )
            } catch (throwable: Throwable) {
                throw DecodeErrorException("message " + throwable.message)
            }
        }

        private fun parseCertificateEntries(buffer: Buffer): List<X509Certificate> {
            var remainingCertificateBytes =
                ((buffer.readByte().toInt() and 0xff) shl 16) or ((buffer.readByte()
                    .toInt() and 0xff) shl 8) or (buffer.readByte().toInt() and 0xff)

            val certificateChain: MutableList<X509Certificate> = arrayListOf()
            while (remainingCertificateBytes > 0) {
                val certSize = ((buffer.readByte().toInt() and 0xff) shl 16) or ((buffer.readByte()
                    .toInt() and 0xff) shl 8) or (buffer.readByte().toInt() and 0xff)
                val certificateData = buffer.readByteArray(certSize)

                if (certSize > 0) {
                    // https://tools.ietf.org/html/rfc8446#section-4.4.2
                    // "If the corresponding certificate payloadType extension ("server_certificate_type" or "client_certificate_type")
                    // was not negotiated in EncryptedExtensions, or the X.509 certificate payloadType was negotiated, then each
                    // CertificateEntry contains a DER-encoded X.509 certificate."
                    // This implementation does not support raw-public-key certificates, so the only payloadType supported is X509.
                    try {
                        certificateChain.add(X509Certificate.decodeFromDer(certificateData))

                    } catch (_: Throwable) {
                        throw BadCertificateAlert("could not parse certificate")
                    }
                }

                remainingCertificateBytes -= (3 + certSize)

                val extensionsSize = buffer.readShort().toInt() and 0xffff
                // https://tools.ietf.org/html/rfc8446#section-4.4.2
                // "Valid extensions for server certificates at present include the OCSP Status extension [RFC6066]
                // and the SignedCertificateTimestamp extension [RFC6962];..."
                // None of them is (yet) supported by this implementation.
                buffer.skip(extensionsSize.toLong()) // extensionData

                remainingCertificateBytes -= (2 + extensionsSize)
            }
            return certificateChain
        }

        private fun serialize(certificate: Certificate): ByteArray {
            val nrOfCerts = 1
            val encodedCerts: MutableList<ByteArray> = mutableListOf()
            encodedCerts.add(certificate.x509.encoded())


            val msgSize =
                4 + 1 + 3 + nrOfCerts * (3 + 2) + encodedCerts.sumOf { bytes: ByteArray -> bytes.size }
            val buffer = Buffer()

            buffer.writeInt((HandshakeType.CERTIFICATE.value.toInt() shl 24) or (msgSize - 4))
            // cert request context size
            buffer.writeByte(0x00.toByte())
            // certificate_list size (3 bytes)
            buffer.writeByte(0.toByte()) // assuming < 65535
            buffer.writeShort((msgSize - 4 - 1 - 3).toShort())

            encodedCerts.forEach { encodedCert: ByteArray ->
                if (encodedCert.size > 0xfff0) {
                    throw RuntimeException("Certificate size not supported")
                }
                // certificate size
                buffer.writeByte(0.toByte())
                buffer.writeShort(encodedCert.size.toShort())
                // certificate
                buffer.write(encodedCert)
                // extensions size
                buffer.writeShort(0.toShort())
            }
            require(buffer.size.toInt() == msgSize)
            return buffer.readByteArray()
        }

    }

}
