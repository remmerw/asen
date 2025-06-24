package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDH

internal class TlsClientEngine(
    private val serverName: String?,
    private val certificate: Certificate,
    private val supportedCiphers: List<CipherSuite>,
    private val requestedExtensions: List<Extension>,
    private val sender: ClientMessageSender,
    private val statusHandler: TlsStatusEventHandler
) : TlsEngine(certificate.publicKey), ClientMessageProcessor {
    private var selectedCipher: CipherSuite? = null
    private lateinit var sentExtensions: List<Extension>
    private var status = Status.Initial
    private var transcriptHash: TranscriptHash? = null
    private lateinit var supportedSignatures: List<SignatureScheme>
    private var pskAccepted = false
    private var clientAuthRequested = false
    private lateinit var serverSupportedSignatureSchemes: List<SignatureScheme>


    suspend fun startHandshake() {
        val signatureSchemes = listOf(
            SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.ECDSA_SECP256R1_SHA256
        )
        startHandshake(signatureSchemes)
    }


    private suspend fun startHandshake(signatureSchemes: List<SignatureScheme>) {
        if (signatureSchemes
                .any { scheme: SignatureScheme -> !AVAILABLE_SIGNATURES.contains(scheme) }
        ) {
            // Remove available leaves the ones that are not available (cannot be supported)
            val unsupportedSignatures = mutableListOf<SignatureScheme>()
            unsupportedSignatures.addAll(signatureSchemes)
            unsupportedSignatures.removeAll(AVAILABLE_SIGNATURES)
            throw IllegalArgumentException("Unsupported signature scheme(s): $unsupportedSignatures")
        }

        supportedSignatures = signatureSchemes

        check(!(serverName == null || supportedCiphers.isEmpty())) { "not all mandatory properties are set" }

        transcriptHash = TranscriptHash()

        val ecdh = CryptographyProvider.Default.get(ECDH)
        val privateKey = ecdh.privateKeyDecoder(EC.Curve.P256).decodeFromByteArrayBlocking(
            EC.PrivateKey.Format.RAW,
            certificate.privateKey.encodeToByteArrayBlocking(EC.PrivateKey.Format.RAW)
        )

        state = TlsState(privateKey, transcriptHash!!)

        val clientHello = ClientHello.createClientHello(
            serverName,
            publicKey,
            false,
            supportedCiphers,
            supportedSignatures,
            NamedGroup.SECP256r1,
            requestedExtensions,
            PskKeyEstablishmentMode.PSK_DHE
        )
        sentExtensions = clientHello.extensions
        sender.send(clientHello)
        status = Status.ClientHelloSent

        transcriptHash!!.record(clientHello)
        state!!.computeEarlyTrafficSecret()
    }

    /**
     * Updates the (handshake) state with a received Server Hello message.
     */

    override fun received(serverHello: ServerHello) {
        val containsSupportedVersionExt = serverHello.extensions.any()
        { ext: Extension? -> ext is SupportedVersionsExtension }
        val containsKeyExt = serverHello.extensions.any()
        { ext: Extension? -> ext is PreSharedKeyExtension || ext is KeyShareExtension }
        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "All TLS 1.3 ServerHello messages MUST contain the "supported_versions" extension.
        // Current ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share"
        // extension, or both (when using a PSK with (EC)DHE key establishment)."
        if (!containsSupportedVersionExt || !containsKeyExt) {
            throw MissingExtensionAlert()
        }

        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        // "A server which negotiates TLS 1.3 MUST respond by sending a "supported_versions" extension containing the selected version value (0x0304)."
        val tlsVersion = serverHello.extensions
            .filter { extension: Extension? -> extension is SupportedVersionsExtension }
            .map { extension: Extension -> (extension as SupportedVersionsExtension).tlsVersion }
            .first()

        if (tlsVersion.toInt() != 0x0304) {
            throw IllegalParameterAlert("invalid tls version")
        }


        // https://tools.ietf.org/html/rfc8446#section-4.2
        // "If an implementation receives an extension which it recognizes and which is not specified for the message in
        // which it appears, it MUST abort the handshake with an "illegal_parameter" alert."
        if (serverHello.extensions
                .any { ext: Extension? -> ext !is SupportedVersionsExtension && ext !is PreSharedKeyExtension && ext !is KeyShareExtension }
        ) {
            throw IllegalParameterAlert("illegal extension in server hello")
        }

        val keyShare = serverHello.extensions
            .filter { extension: Extension? -> extension is KeyShareExtension }  // In the context of a server hello, the key share extension contains exactly one key share entry
            .map { extension: Extension -> (extension as KeyShareExtension).keyShareEntries[0] }


        val preSharedKey = serverHello.extensions
            .filter { extension: Extension? -> extension is ServerPreSharedKeyExtension }


        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share" extension,
        // or both (when using a PSK with (EC)DHE key establishment)."
        if (keyShare.isEmpty() && preSharedKey.isEmpty()) {
            throw MissingExtensionAlert(" either the pre_shared_key extension or the key_share extension must be present")
        }

        if (preSharedKey.isNotEmpty()) {
            // https://tools.ietf.org/html/rfc8446#section-4.2.11
            // "In order to accept PSK key establishment, the server sends a "pre_shared_key" extension indicating the selected identity."
            pskAccepted = true
        }

        if (!supportedCiphers.contains(serverHello.cipherSuite)) {
            // https://tools.ietf.org/html/rfc8446#section-4.1.3
            // "A client which receives a cipher suite that was not offered MUST abort the handshake with an "illegal_parameter" alert."
            throw IllegalParameterAlert("cipher suite does not match")
        }
        selectedCipher = serverHello.cipherSuite

        if (preSharedKey.isNotEmpty()) {
            state!!.setPskSelected()
        } else {
            state!!.setNoPskSelected()
        }
        if (keyShare.isNotEmpty()) {
            state!!.setPeerKey(keyShare.first().key())
            state!!.computeSharedSecret()
        }
        transcriptHash!!.record(serverHello)
        state!!.computeHandshakeSecrets()
        status = Status.ServerHelloReceived
        statusHandler.handshakeSecretsKnown()
    }

    override suspend fun received(
        encryptedExtensions: EncryptedExtensions,
        protectionKeysType: ProtectionKeysType
    ) {
        if (protectionKeysType != ProtectionKeysType.Handshake) {
            throw UnexpectedMessageAlert("incorrect protection level")
        }
        if (status != Status.ServerHelloReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.3.1
            // "the server MUST send the EncryptedExtensions message immediately after the ServerHello message"
            throw UnexpectedMessageAlert("unexpected encrypted extensions message")
        }

        val clientExtensionTypes: List<ExtensionClass> = sentExtensions
            .map { obj: Extension -> obj.extension() }.toList()
        val allClientResponses = encryptedExtensions.extensions
            .filter { ext: Extension? -> ext !is UnknownExtension }
            .all { ext: Extension -> clientExtensionTypes.contains(ext.extension()) }
        if (!allClientResponses) {
            // https://tools.ietf.org/html/rfc8446#section-4.2
            // "Implementations MUST NOT send extension responses if the remote endpoint did not
            // send the corresponding extension requests, with the exception of the "cookie"
            // extension in the HelloRetryRequest. Upon receiving
            // such an extension, an endpoint MUST abort the handshake with an
            // "unsupported_extension" alert."
            throw UnsupportedExtensionAlert("extension response to missing request")
        }

        val uniqueExtensions = encryptedExtensions.extensions
            .map { obj: Extension -> obj.extension() }
            .toSet()
            .size
        if (uniqueExtensions != encryptedExtensions.extensions.size) {
            // "There MUST NOT be more than one extension of the same payloadType in a given extension block."
            throw UnsupportedExtensionAlert("duplicate extensions not allowed")
        }

        transcriptHash!!.record(encryptedExtensions)
        status = Status.EncryptedExtensionsReceived
        statusHandler.extensionsReceived(encryptedExtensions.extensions)
    }

    override fun received(
        certificateMessage: CertificateMessage,
        protectionKeysType: ProtectionKeysType
    ) {
        if (protectionKeysType != ProtectionKeysType.Handshake) {
            throw UnexpectedMessageAlert("incorrect protection level")
        }
        if (status != Status.EncryptedExtensionsReceived && status != Status.CertificateRequestReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.4
            // "TLS generally uses a common set of messages for authentication, key confirmation, and handshake
            //   integrity: Certificate, CertificateVerify, and Finished.  (...)  These three messages are always
            //   sent as the last messages in their handshake flight."
            throw UnexpectedMessageAlert("unexpected certificate message")
        }

        if (certificateMessage.requestContext.isNotEmpty()) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.2
            // "If this message is in response to a CertificateRequest, the value of certificate_request_context in that
            // message. Otherwise (in the case of server authentication), this field SHALL be zero length."
            throw IllegalParameterAlert("certificate request context should be zero length")
        }

        remoteCertificate = certificateMessage.endEntityCertificate
        transcriptHash!!.recordServer(certificateMessage)
        status = Status.CertificateReceived
    }

    override fun received(
        certificateVerifyMessage: CertificateVerifyMessage,
        protectionKeysType: ProtectionKeysType
    ) {
        if (protectionKeysType != ProtectionKeysType.Handshake) {
            throw UnexpectedMessageAlert("incorrect protection level")
        }
        if (status != Status.CertificateReceived) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.3
            // "When sent, this message MUST appear immediately after the Certificate message and immediately prior to
            // the Finished message."
            throw UnexpectedMessageAlert("unexpected certificate verify message")
        }

        val signatureScheme = certificateVerifyMessage.signatureScheme
        if (!supportedSignatures.contains(signatureScheme)) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.3
            // "If the CertificateVerify message is sent by a server, the signature algorithm MUST be one offered in
            // the client's "signature_algorithms" extension"
            throw IllegalParameterAlert("signature scheme does not match")
        }


        if (!verifySignature(
                signatureScheme, remoteCertificate!!,
                transcriptHash!!.getServerHash(HandshakeType.CERTIFICATE)
            )
        ) {
            throw DecryptErrorAlert("signature verification fails")
        }


        transcriptHash!!.recordServer(certificateVerifyMessage)
        status = Status.CertificateVerifyReceived
    }

    override suspend fun received(
        finishedMessage: FinishedMessage,
        protectionKeysType: ProtectionKeysType
    ) {
        if (protectionKeysType != ProtectionKeysType.Handshake) {
            throw UnexpectedMessageAlert("incorrect protection level")
        }
        val expectedStatus = if (pskAccepted) {
            Status.EncryptedExtensionsReceived
        } else {
            Status.CertificateVerifyReceived
        }
        if (status != expectedStatus) {
            throw UnexpectedMessageAlert("unexpected finished message")
        }

        transcriptHash!!.recordServer(finishedMessage)

        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     +-----------+-------------------------+-----------------------------+
        //     | Server    | ClientHello ... later   | server_handshake_traffic_   |
        //     |           | of EncryptedExtensions/ | secret                      |
        //     |           | CertificateRequest      |                             |"
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        // "The verify_data value is computed as follows:
        //   verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
        //      * Only included if present."
        val serverHmac = computeFinishedVerifyData(
            transcriptHash!!.getServerHash(HandshakeType.CERTIFICATE_VERIFY),
            state!!.serverHandshakeTrafficSecret
        )
        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "Recipients of Finished messages MUST verify that the contents are correct and if incorrect MUST terminate the connection with a "decrypt_error" alert."
        if (!finishedMessage.verifyData.contentEquals(serverHmac)) {
            throw DecryptErrorAlert("incorrect finished message")
        }

        if (clientAuthRequested) {
            sendClientAuth()
        }

        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     | Client    | ClientHello ... later   | client_handshake_traffic_   |
        //     |           | of server               | secret                      |
        //     |           | Finished/EndOfEarlyData |                             |"
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        // "The verify_data value is computed as follows:
        //   verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
        //      * Only included if present."
        val clientHmac = computeFinishedVerifyData(
            transcriptHash!!.getClientHash(HandshakeType.CERTIFICATE_VERIFY),
            state!!.clientHandshakeTrafficSecret
        )
        val clientFinished = FinishedMessage.createFinishedMessage(clientHmac)
        sender.send(clientFinished)

        transcriptHash!!.recordClient(clientFinished)
        state!!.computeApplicationSecrets()
        status = Status.Finished
        statusHandler.handshakeFinished()
    }


    override fun received(
        certificateRequestMessage: CertificateRequestMessage,
        protectionKeysType: ProtectionKeysType
    ) {
        if (protectionKeysType != ProtectionKeysType.Handshake) {
            throw UnexpectedMessageAlert("incorrect protection level")
        }
        if (status != Status.EncryptedExtensionsReceived) {
            throw UnexpectedMessageAlert("unexpected certificate request message")
        }


        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
        // "The "signature_algorithms" extension MUST be specified..."
        val extension =
            certificateRequestMessage.extensions.first { extension: Extension ->
                extension is SignatureAlgorithmsExtension
            }

        serverSupportedSignatureSchemes = (extension as SignatureAlgorithmsExtension).algorithms



        if (serverSupportedSignatureSchemes.isEmpty()) {
            MissingExtensionAlert()
        }

        transcriptHash!!.record(certificateRequestMessage)

        /* Not used
        Arrays.stream(certificateRequestMessage.extensions)
            .filter { extension: Extension? -> extension is CertificateAuthoritiesExtension }
            .findFirst()
            .map { extension: Extension -> (extension as CertificateAuthoritiesExtension).authorities }
            .orElse(PRINCIPALS_EMPTY)*/

        clientAuthRequested = true

        status = Status.CertificateRequestReceived
    }

    private suspend fun sendClientAuth() {
        val certificateMessage =
            CertificateMessage.createCertificateMessage(certificate)
        sender.send(certificateMessage)
        transcriptHash!!.recordClient(certificateMessage)

        // When certificate is sent, also send a certificate verify message
        val selectedSignatureSchemeList = serverSupportedSignatureSchemes
            .filter { o: SignatureScheme -> supportedSignatures.contains(o) }
            .filter { scheme: SignatureScheme ->
                certificateSupportsSignature(certificate, scheme)
            }
        if (selectedSignatureSchemeList.isEmpty()) {
            HandshakeFailureAlert("failed to negotiate signature scheme")
        }
        val selectedSignatureScheme = selectedSignatureSchemeList.first()

        val hash = transcriptHash!!.getClientHash(HandshakeType.CERTIFICATE)
        val signature = computeSignature(hash, certificate)
        val certificateVerify =
            CertificateVerifyMessage.createCertificateVerifyMessage(
                selectedSignatureScheme, signature
            )
        sender.send(certificateVerify)
        transcriptHash!!.recordClient(certificateVerify)
    }


    fun getSelectedCipher(): CipherSuite {
        if (selectedCipher != null) {
            return selectedCipher!!
        } else {
            throw IllegalStateException("No (valid) server hello received yet")
        }
    }


    private fun certificateSupportsSignature(
        certificate: Certificate,
        signatureScheme: SignatureScheme
    ): Boolean {
        return certificate.scheme == signatureScheme
    }

}

