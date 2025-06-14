package io.github.remmerw.asen.quic

import at.asitplus.signum.indispensable.pki.X509Certificate
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import io.github.remmerw.asen.debug
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

internal val AVAILABLE_SIGNATURES: List<SignatureScheme> = listOf(
    SignatureScheme.RSA_PSS_RSAE_SHA256,
    SignatureScheme.RSA_PSS_RSAE_SHA384,
    SignatureScheme.RSA_PSS_RSAE_SHA512,
    SignatureScheme.ECDSA_SECP256R1_SHA256
)


internal const val LABEL_PREFIX = "tls13 "

// Assuming AES-128, use 32 for AES-256
internal const val HASH_LENGTH: Short = 32 // Assuming SHA-256, use 48 for SHA-384


internal fun validateExtensionHeader(
    buffer: Buffer,
    extensionLength: Int,
    minimumExtensionSize: Int
): Int {
    if (extensionLength < minimumExtensionSize) {
        throw DecodeErrorException("Can't be less than $minimumExtensionSize bytes")
    }
    if (buffer.size < extensionLength) {
        throw DecodeErrorException("extension underflow")
    }
    return extensionLength
}

internal fun parseExtensions(
    buffer: Buffer,
    context: HandshakeType,
    customExtensionParser: ExtensionParser? = null
): List<Extension> {
    if (buffer.size < 2) {
        throw DecodeErrorException("Extension field must be at least 2 bytes long")
    }
    val extensions = ArrayList<Extension>()

    var remainingExtensionsLength = buffer.readShort().toInt() and 0xffff
    if (buffer.size < remainingExtensionsLength) {
        throw DecodeErrorException("Extensions too short")
    }

    while (remainingExtensionsLength >= 4) {

        val extensionType = buffer.readShort().toInt() and 0xffff
        val extensionLength = buffer.readShort().toInt() and 0xffff
        remainingExtensionsLength -= 4

        if (extensionLength > remainingExtensionsLength) {
            throw DecodeErrorException("Extension length exceeds extensions length")
        }


        if (extensionType == ExtensionType.SERVER_NAME.value.toInt()) {
            extensions.add(ServerNameExtension.parse(buffer, extensionLength))
        } else if (extensionType == ExtensionType.SUPPORTED_GROUPS.value.toInt()) {
            extensions.add(SupportedGroupsExtension.parse(buffer, extensionLength))
        } else if (extensionType == ExtensionType.SIGNATURE_ALGORITHMS.value.toInt()) {
            extensions.add(SignatureAlgorithmsExtension.parse(buffer, extensionLength))
        } else if (extensionType == ExtensionType.APPLICATION_LAYER_PROTOCOL.value.toInt()) {
            extensions.add(
                ApplicationLayerProtocolNegotiationExtension.parse(
                    buffer,
                    extensionLength
                )
            )
        } else if (extensionType == ExtensionType.PRE_SHARED_KEY.value.toInt()) {
            when (context) {
                HandshakeType.SERVER_HELLO -> {
                    extensions.add(ServerPreSharedKeyExtension.parse(buffer, extensionLength))
                }

                HandshakeType.CLIENT_HELLO -> {
                    extensions.add(
                        ClientHelloPreSharedKeyExtension.parse(
                            buffer,
                            extensionLength
                        )
                    )
                }

                else -> {
                    throw IllegalParameterAlert("Extension not allowed in " + context.value)
                }
            }
        } else if (extensionType == ExtensionType.EARLY_DATA.value.toInt()) {
            extensions.add(EarlyDataExtension.parse(buffer, extensionLength, context))
        } else if (extensionType == ExtensionType.SUPPORTED_VERSIONS.value.toInt()) {
            extensions.add(SupportedVersionsExtension.parse(buffer, extensionLength, context))
        } else if (extensionType == ExtensionType.ASK_KEY_EXCHANGE_MODES.value.toInt()) {
            extensions.add(PskKeyExchangeModesExtension.parse(buffer, extensionLength))
        } else if (extensionType == ExtensionType.CERTIFICATE_AUTHORITIES.value.toInt()) {
            extensions.add(CertificateAuthoritiesExtension.parse(buffer, extensionLength))
        } else if (extensionType == ExtensionType.KEY_SHARE.value.toInt()) {
            extensions.add(KeyShareExtension.create(buffer, extensionLength, context))
        } else {
            var extension: Extension? = null
            if (customExtensionParser != null) {
                extension =
                    customExtensionParser.apply(buffer, extensionType, extensionLength, context)
            }
            if (extension != null) {
                extensions.add(extension)
            } else {
                extensions.add(UnknownExtension.parse(buffer, extensionType, extensionLength))
            }
        }

        remainingExtensionsLength -= extensionLength
    }

    return extensions
}

internal fun parseHandshakeHeader(
    buffer: Buffer,
    minimumMessageSize: Int
): Int {
    if (buffer.size < 4) {
        throw DecodeErrorException("handshake message underflow")
    }

    val messageDataLength = ((buffer.readByte().toInt() and 0xff) shl 16) or ((buffer.readByte()
        .toInt() and 0xff) shl 8) or (buffer.readByte().toInt() and 0xff)
    if (4 + messageDataLength < minimumMessageSize) {
        throw DecodeErrorException("HandshakeMessage can't be less than $minimumMessageSize bytes")
    }
    if (buffer.size < messageDataLength) {
        throw DecodeErrorException("handshake message underflow")
    }
    return messageDataLength
}

/**
 * Compute the signature used in certificate verify message to proof possession of private key.
 */
internal fun computeSignature(
    content: ByteArray, certificate: Certificate
): ByteArray {
    // https://tools.ietf.org/html/rfc8446#section-4.4.3

    //   The digital signature is then computed over the concatenation of:
    //   -  A string that consists of octet 32 (0x20) repeated 64 times
    //   -  The context string
    //   -  A single 0 byte which serves as the separator
    //   -  The content to be signed"

    Buffer().use { signatureInput ->
        signatureInput.write(
            byteArrayOf(0x20).decodeToString().repeat(64).encodeToByteArray()
        )
        val contextString = "TLS 1.3, " + ("client") + " CertificateVerify"
        signatureInput.write(contextString.encodeToByteArray())
        signatureInput.writeByte(0x00.toByte())
        signatureInput.write(content)

        val generator = certificate.privateKey.signatureGenerator(
            SHA256,
            ECDSA.SignatureFormat.DER
        )
        return generator.generateSignatureBlocking(signatureInput.readByteArray())
    }
}

internal fun verifySignature(
    signatureScheme: SignatureScheme,
    certificate: X509Certificate,
    transcriptHash: ByteArray
): Boolean {
    // https://tools.ietf.org/html/rfc8446#section-4.4.3
    // "The digital signature is then computed over the concatenation of:
    //   -  A string that consists of octet 32 (0x20) repeated 64 times
    //   -  The context string
    //   -  A single 0 byte which serves as the separator
    //   -  The content to be signed"
    val contextString = "TLS 1.3, " + ("server") + " CertificateVerify"
    val size = 64 + contextString.encodeToByteArray().size + 1 + transcriptHash.size

    val contentToSign = Buffer()
    repeat(64) {
        contentToSign.writeByte(0x20.toByte())
    }
    // "The context string for a server signature is
    //   "TLS 1.3, server CertificateVerify". "
    contentToSign.write(contextString.encodeToByteArray())
    contentToSign.writeByte(0x00.toByte())
    // "The content that is covered
    //   under the signature is the hash output as described in Section 4.4.1,
    //   namely:
    //      Transcript-Hash(Handshake Context, Certificate)"
    contentToSign.write(transcriptHash)
    require(size == contentToSign.size.toInt())

    // https://tools.ietf.org/html/rfc8446#section-9.1
    // "A TLS-compliant application MUST support digital signatures with rsa_pkcs1_sha256 (for certificates),
    // rsa_pss_rsae_sha256 (for CertificateVerify and certificates), and ecdsa_secp256r1_sha256."
    return when (signatureScheme) {
        SignatureScheme.RSA_PSS_RSAE_SHA256 -> {
            debug("RSA_PSS_RSAE_SHA256")
            throw HandshakeFailureAlert("Signature algorithm not supported $signatureScheme")
        }

        SignatureScheme.RSA_PSS_RSAE_SHA384 -> {
            debug("RSA_PSS_RSAE_SHA384")
            throw HandshakeFailureAlert("Signature algorithm not supported $signatureScheme")
        }

        SignatureScheme.RSA_PSS_PSS_SHA512 -> {
            debug("RSA_PSS_PSS_SHA512")
            throw HandshakeFailureAlert("Signature algorithm not supported $signatureScheme")
        }

        SignatureScheme.ECDSA_SECP256R1_SHA256 -> {
            val ecdsa = CryptographyProvider.Default.get(ECDSA)

            val serverPublicKey = ecdsa.publicKeyDecoder(EC.Curve.P256)
                .decodeFromByteArrayBlocking(
                    EC.PublicKey.Format.DER,
                    certificate.publicKey.encodeToDer()
                )

            val verifier2 = serverPublicKey.signatureVerifier(SHA256, ECDSA.SignatureFormat.DER)
            return verifier2.tryVerifySignatureBlocking(
                certificate.tbsCertificate.encodeToDer(),
                certificate.signature.encodeToDer()
            )
        }

        else -> {
            // Bad luck, not (yet) supported.
            throw HandshakeFailureAlert("Signature algorithm not supported $signatureScheme")
        }
    }
}