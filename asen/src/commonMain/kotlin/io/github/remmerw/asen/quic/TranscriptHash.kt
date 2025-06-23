package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlinx.io.Buffer


// https://tools.ietf.org/html/rfc8446#section-4.4.1
// "Many of the cryptographic computations in TLS make use of a transcript hash. This value is computed by hashing the
//  concatenation of each included handshake message, including the handshake message header carrying the handshake
//  message payloadType and length fields, but not including record layer headers."
internal class TranscriptHash {


    private val msgData: MutableMap<Int, ByteArray> = mutableMapOf()
    private val hashes: MutableMap<Int, ByteArray> = mutableMapOf()


    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated message payloadType.
     */
    fun getHash(msgType: HandshakeType): ByteArray {
        return getHash(convert(msgType))
    }

    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated client message payloadType.
     * For example, when the `msgType` parameter has value `certificate`, the transcript hash for
     * the concatenation of handshake messages up to (and including) the client certificate message is returned.
     */
    fun getClientHash(msgType: HandshakeType): ByteArray {
        return getHash(convert(msgType, true))
    }

    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated server message payloadType.
     * For example, when the `msgType` parameter has value `certificate`, the transcript hash for
     * the concatenation of handshake messages up to (and including) the server certificate message is returned.
     */
    fun getServerHash(msgType: HandshakeType): ByteArray {
        return getHash(convert(msgType, false))
    }

    /**
     * Record a handshake message for computing the transcript hash. The payloadType of the message determines its position
     * in the transcript hash computation.
     */
    fun record(msg: HandshakeMessage) {
        require(!ambigousTypes.contains(msg.type))
        msgData[convert(msg.type)] = msg.bytes
    }

    /**
     * Record a client handshake message for computing the transcript hash. This method is needed because the
     * `TlsConstants.HandshakeType` payloadType does not differentiate between client and server variants, whilst
     * these variants have a different position in the transcript hash computation.
     * Note that the term "client" here refers to the message payloadType, not whether it is sent or received by a client.
     * For example, a client certificate message is sent by the client and received by the server; both need to use
     * this method to record the message.
     */
    fun recordClient(msg: HandshakeMessage) {
        msgData[convert(msg.type, true)] = msg.bytes
    }

    /**
     * Record a server handshake message for computing the transcript hash. This method is needed because the
     * `TlsConstants.HandshakeType` payloadType does not differentiate between client and server variants, whilst
     * these variants have a different position in the transcript hash computation.
     * Note that the term "server" here refers to the message payloadType, not whether it is sent or received by a server.
     * For example, a server certificate message is sent by the server and received by the client; both need to use
     * this method to record the message.
     */
    fun recordServer(msg: HandshakeMessage) {
        msgData[convert(msg.type, false)] = msg.bytes
    }

    private fun getHash(ordinal: Int): ByteArray {
        if (!hashes.containsKey(ordinal)) {
            computeHash(ExtendedHandshakeType.get(ordinal))
        }
        return hashes[ordinal]!!
    }

    private fun computeHash(requestedType: ExtendedHandshakeType) {
        val buffer = Buffer()
        for (type in hashedMessages) {
            val data = msgData[type.ordinal]
            if (data != null) {
                buffer.write(data)
            }
            if (type == requestedType) {
                break
            }
        }
        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        hashes[requestedType.ordinal] = CryptographyProvider.Default
            .get(SHA256)
            .hasher()
            .hashBlocking(buffer)
            .toByteArray()
    }

    private val ambigousTypes: List<HandshakeType> = listOf(
        HandshakeType.CERTIFICATE,
        HandshakeType.CERTIFICATE_VERIFY, HandshakeType.FINISHED
    )

    // https://tools.ietf.org/html/rfc8446#section-4.4.1
    // "For concreteness, the transcript hash is always taken from the
    //   following sequence of handshake messages, starting at the first
    //   ClientHello and including only those messages that were sent:
    //   ClientHello, HelloRetryRequest, ClientHello, ServerHello,
    //   EncryptedExtensions, server CertificateRequest, server Certificate,
    //   server CertificateVerify, server Finished, EndOfEarlyData, client
    //   Certificate, client CertificateVerify, client Finished."
    private val hashedMessages = arrayOf(
        ExtendedHandshakeType.CLIENT_HELLO,
        ExtendedHandshakeType.SERVER_HELLO,
        ExtendedHandshakeType.ENCRYPTED_EXTENSIONS,
        ExtendedHandshakeType.CERTIFICATE_REQUEST,
        ExtendedHandshakeType.SERVER_CERTIFICATE,
        ExtendedHandshakeType.SERVER_CERTIFICATE_VERIFY,
        ExtendedHandshakeType.SERVER_FINISHED,
        ExtendedHandshakeType.CLIENT_CERTIFICATE,
        ExtendedHandshakeType.CLIENT_CERTIFICATE_VERIFY,
        ExtendedHandshakeType.CLIENT_FINISHED
    )

    private fun convert(type: HandshakeType): Int {
        require(!ambigousTypes.contains(type)) { "cannot convert ambiguous payloadType $type" }
        return type.ordinal
    }

    private fun convert(type: HandshakeType, client: Boolean): Int {
        return when (type) {
            HandshakeType.FINISHED -> {
                if (client) ExtendedHandshakeType.CLIENT_FINISHED.ordinal else
                    ExtendedHandshakeType.SERVER_FINISHED.ordinal
            }

            HandshakeType.CERTIFICATE -> {
                if (client) ExtendedHandshakeType.CLIENT_CERTIFICATE.ordinal else
                    ExtendedHandshakeType.SERVER_CERTIFICATE.ordinal
            }

            HandshakeType.CERTIFICATE_VERIFY -> {
                if (client) ExtendedHandshakeType.CLIENT_CERTIFICATE_VERIFY.ordinal
                else ExtendedHandshakeType.SERVER_CERTIFICATE_VERIFY.ordinal
            }

            else -> type.ordinal
        }
    }

}
