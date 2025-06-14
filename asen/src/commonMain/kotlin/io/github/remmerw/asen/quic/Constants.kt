package io.github.remmerw.asen.quic


// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
// 0x00	original_destination_connection_id	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x01	max_idle_timeout	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x02	stateless_reset_token	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x03	max_udp_payload_size	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x04	initial_max_data	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x05	initial_max_stream_data_bidi_local	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x06	initial_max_stream_data_bidi_remote	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x07	initial_max_stream_data_uni	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x08	initial_max_streams_bidi	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x09	initial_max_streams_uni	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0a	ack_delay_exponent	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0b	max_ack_delay	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0c	disable_active_migration	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0d	preferred_address	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0e	active_connection_id_limit	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x0f	initial_source_connection_id	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x10	retry_source_connection_id	permanent	[RFC9000, Section 18.2]	2021-02-11	IETF	[QUIC_WG]
//0x11	version_information	permanent	[RFC9368]	2022-12-16	IETF	[QUIC_WG]
//0x20	max_datagram_frame_size	permanent	[RFC9221]	2021-10-20	IETF	[QUIC_WG]
//0x173e	discard	provisional	[https://github.com/quicwg/base-drafts/wiki/Quantum-Readiness-test]	2022-06-02	[David_Schinazi]	[David_Schinazi]	Receiver silently discards.
//0x26ab	google handshake message	provisional		2022-11-01	Google	[Google]	Used to carry Google internal handshake message
//0x2ab2	grease_quic_bit	permanent	[RFC9287]	2022-07-13	IETF	[QUIC_WG]
//0x3127	initial_rtt	provisional		2021-10-20	Google	[Google]	Initial RTT in microseconds
//0x3128	google_connection_options	provisional		2021-10-20	Google	[Google]	Google connection options for experimentation
//0x3129	user_agent	provisional		2021-10-20	Google	[Google]	User agent string (deprecated)
//0x4752	google_version	provisional		2021-10-20	Google	[Google]	Google QUIC version downgrade prevention
//0x0f739bbc1b666d05	enable_multipath	provisional	[draft-ietf-quic-multipath-05, Section 3]	2023-07-26	Yanmei Liu	[Yanmei_Liu]


@Suppress("RedundantSuppression", "unused")
internal enum class TransportParameterId(val value: Int) {
    ORIGINAL_DESTINATION_CID(0),
    MAX_IDLE_TIMEOUT(1),
    STATELESS_RESET_TOKEN(2),
    MAX_UDP_PAYLOAD_SIZE(3),
    INITIAL_MAX_DATA(4),
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL(5),
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE(6),
    INITIAL_MAX_STREAM_DATA_UNI(7),
    INITIAL_MAX_STREAMS_BIDI(8),
    INITIAL_MAX_STREAMS_UNI(9),
    ACK_DELAY_EXPONENT(0x0a),
    MAX_ACK_DELAY(0x0b),
    DISABLE_ACTIVE_MIGRATION(0x0c),
    PREFERRED_ADDRESS(0x0d),
    ACTIVE_CONNECTION_ID_LIMIT(0x0e),
    INITIAL_SOURCE_CID(0x0f),
    RETRY_SOURCE_CID(0x10),

    // https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-05.html#name-quic-transport-parameter
    // // https://www.iana.org/assignments/quic/quic.xhtml
    VERSION_INFORMATION(0x11),

    MAX_DATAGRAM_FRAME_SIZE(0x0020)
}

internal enum class BlockReason {
    DATA_BLOCKED,
    STREAM_DATA_BLOCKED,
    NOT_BLOCKED
}

internal enum class ExtensionClass {
    EARLY_DATA,
    TRANSPORT_PARAMETERS,
    PROTOCOL_NEGOTIATION,
    CERTIFICATE_AUTHORITIES,
    CLIENT_HELLO_PRE_SHARED_KEY,
    KEY_SHARE,
    PSK_KEY_EXCHANGE_MODES,
    SERVER_NAME,
    SERVER_PRE_SHARED_KEY,
    SIGNATURE_ALGORITHMS,
    SUPPORTED_GROUPS,
    SUPPORTED_VERSIONS,
    UNKNOWN;
}

internal enum class PskKeyEstablishmentMode {
    NONE,
    PSK_ONLY,
    PSK_DHE,
    BOTH
}


@Suppress("unused")
internal enum class Status {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    EncryptedExtensionsReceived,
    CertificateRequestReceived,
    CertificateReceived,
    CertificateVerifyReceived,
    Finished,
    ClientHelloReceived,
    ServerHelloSent,
    EncryptedExtensionsSent,
    CertificateRequestSent,
    CertificateSent,
    CertificateVerifySent,
    FinishedSent,
    FinishedReceived
}


internal enum class HandshakeState {
    Initial,
    HasHandshakeKeys,
    HasAppKeys,
    Confirmed;

    fun transitionAllowed(proposedState: HandshakeState): Boolean {
        return this.ordinal < proposedState.ordinal
    }
}

internal enum class FrameType {
    AckFrame, CryptoFrame, StreamFrame, ConnectionCloseFrame,
    DataBlockedFrame, StreamDataBlockedFrame, HandshakeDoneFrame,
    MaxDataFrame, PingFrame, PaddingFrame, NewTokenFrame,
    ResetStreamFrame, MaxStreamDataFrame, MaxStreamsFrame,
    NewConnectionIdFrame, PathChallengeFrame, PathResponseFrame,
    RetireConnectionIdFrame, StopSendingFrame, StreamsBlockedFrame
}

@Suppress("RedundantSuppression", "unused")
enum class SignatureScheme(value: Int) {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RSA_PKCS1_SHA256(0x0401),
    RSA_PKCS1_SHA384(0x0501),
    RSA_PKCS1_SHA512(0x0601),

    /* ECDSA algorithms */
    ECDSA_SECP256R1_SHA256(0x0403),
    ECDSA_SECP384R1_SHA384(0x0503),
    ECDSA_SECP521R1_SHA512(0x0603),

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256(0x0804),
    RSA_PSS_RSAE_SHA384(0x0805),
    RSA_PSS_RSAE_SHA512(0x0806),

    /* EdDSA algorithms */
    ED25519(0x0807),
    ED448(0x0808),

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256(0x0809),
    RSA_PSS_PSS_SHA384(0x080a),
    RSA_PSS_PSS_SHA512(0x080b),

    /* Legacy algorithms */
    RSA_PKCS1_SHA1(0x0201),
    ECDSA_SHA1(0x0203),
    ;

    val value: Short = value.toShort()


    companion object {
        private val byValue: MutableMap<Short, SignatureScheme> = mutableMapOf()

        init {
            for (t in entries) {
                byValue[t.value] = t
            }
        }


        fun get(value: Short): SignatureScheme {
            val signatureScheme = byValue[value]
                ?: throw DecodeErrorException("invalid signature scheme value")
            return signatureScheme
        }
    }
}

internal enum class ProtectionKeysType {
    None,
    Handshake,
    Application
}

@Suppress("RedundantSuppression", "unused")
internal enum class ExtendedHandshakeType {
    CLIENT_HELLO,
    SERVER_HELLO,
    NEW_SESSION_TICKET,
    END_OF_EARLY_DATA,
    ENCRYPTED_EXTENSIONS,
    CERTIFICATE,
    CERTIFICATE_REQUEST,
    CERTIFICATE_VERIFY,
    FINISHED,
    KEY_UPDATE,
    SERVER_CERTIFICATE,
    SERVER_CERTIFICATE_VERIFY,
    SERVER_FINISHED,
    CLIENT_CERTIFICATE,
    CLIENT_CERTIFICATE_VERIFY,
    CLIENT_FINISHED;

    companion object {
        private val byOrdinal: MutableMap<Int, ExtendedHandshakeType> = mutableMapOf()

        init {
            for (t in entries) {
                byOrdinal[t.ordinal] = t
            }
        }


        fun get(ordinal: Int): ExtendedHandshakeType {
            val type = byOrdinal[ordinal]
            checkNotNull(type) { "ExtendedHandshakeType not found" }
            return type
        }
    }
}

@Suppress("RedundantSuppression", "unused")
internal enum class HandshakeType(value: Int) {
    CLIENT_HELLO(1),
    SERVER_HELLO(2),
    NEW_SESSION_TICKET(4),
    END_OF_EARLY_DATA(5),
    ENCRYPTED_EXTENSIONS(8),
    CERTIFICATE(11),
    CERTIFICATE_REQUEST(13),
    CERTIFICATE_VERIFY(15),
    FINISHED(20),
    KEY_UPDATE(24),
    MESSAGE_HASH(254),
    ;

    val value: Byte = value.toByte()


    companion object {
        private val byValue: MutableMap<Int, HandshakeType> = mutableMapOf()

        init {
            for (t in entries) {
                byValue[t.value.toInt()] = t
            }
        }

        fun get(value: Int): HandshakeType? {
            return byValue[value]
        }
    }
}

@Suppress("RedundantSuppression", "unused")
internal enum class NamedGroup(value: Int) {
    /* Elliptic Curve Groups (ECDHE) */
    SECP256r1(0x0017), SECP384r1(0x0018), SECP521r1(0x0019);

    val value: Short = value.toShort()

    companion object {
        private val byValue: MutableMap<Short, NamedGroup> = mutableMapOf()

        init {
            for (t in entries) {
                byValue[t.value] = t
            }
        }


        fun get(value: Short): NamedGroup {
            val namedGroup = byValue[value]
                ?: throw DecodeErrorException("invalid group value")
            return namedGroup
        }
    }
}

@Suppress("RedundantSuppression", "unused")
internal enum class CipherSuite(value: Int) {
    TLS_AES_128_GCM_SHA256(0x1301),
    TLS_AES_256_GCM_SHA384(0x1302),
    TLS_AES_128_CCM_SHA256(0x1304),
    TLS_AES_128_CCM_8_SHA256(0x1305);

    val value: Short = value.toShort()

    companion object {
        private val byValue: MutableMap<Short, CipherSuite> = mutableMapOf()

        init {
            for (t in entries) {
                byValue[t.value] = t
            }
        }

        fun get(value: Short): CipherSuite? {
            return byValue[value]
        }
    }
}


@Suppress("unused")
internal enum class ExtensionType(value: Int) {
    SERVER_NAME(0),  /* RFC 6066 */

    MAX_FRAGMENT_LENGTH(1),  /* RFC 6066 */

    STATUS_REQUEST(5),  /* RFC 6066 */
    SUPPORTED_GROUPS(10),  /* RFC 8422, 7919 */
    SIGNATURE_ALGORITHMS(13),  /* RFC 8446 */

    USE_SRTP(14),  /* RFC 5764 */

    HEARTBEAT(15),  /* RFC 6520 */
    APPLICATION_LAYER_PROTOCOL(16),  /* RFC 7301 */

    SIGNED_CERTIFICATE_TIMESTAMP(18),  /* RFC 6962 */

    CLIENT_CERTIFICATE_TYPE(19),  /* RFC 7250 */

    SERVER_CERTIFICATE_TYPE(20),  /* RFC 7250 */

    PADDING(21),  /* RFC 7685 */
    PRE_SHARED_KEY(41),  /* RFC 8446 */
    EARLY_DATA(42),  /* RFC 8446 */
    SUPPORTED_VERSIONS(43),  /* RFC 8446 */

    COOKIE(44),  /* RFC 8446 */
    ASK_KEY_EXCHANGE_MODES(45),  /* RFC 8446 */
    CERTIFICATE_AUTHORITIES(47),  /* RFC 8446 */

    OID_FILTERS(48),  /* RFC 8446 */

    POST_HANDSHAKE_AUTH(49),  /* RFC 8446 */

    SIGNATURE_ALGORITHMS_CERT(50),  /* RFC 8446 */
    KEY_SHARE(51),
    ;


    val value: Short = value.toShort()
}

@Suppress("RedundantSuppression", "unused")
internal enum class PskKeyExchangeMode(value: Int) {
    PSK_KE(0),
    PSK_DHE_KE(1);

    val value: Byte = value.toByte()
}


@Suppress("RedundantSuppression", "unused")
internal enum class AlertDescription(value: Int) {
    CLOSE_NOTIFY(0),
    UNEXPECTED_MESSAGE(10),

    BAD_RECORD_MAC(20),

    RECORD_OVERFLOW(22),
    HANDSHAKE_FAILURE(40),
    BAD_CERTIFICATE(42),

    UNSUPPORTED_CERTIFICATE(43),

    CERTIFICATE_REVOKE(44),

    CERTIFICATE_EXPIRED(45),
    CERTIFICATE_UNKNOWN(46),
    ILLEGAL_PARAMETER(47),

    UNKNOWN_CA(48),

    ACCESS_DENIED(49),
    DECODE_ERROR(50),
    DECRYPT_ERROR(51),

    PROTOCOL_VERSION(70),

    INSUFFICIENT_SECURITY(71),
    INTERNAL_ERROR(80),

    INAPPROPRIATE_FALLBACK(86),

    USER_CANCELED(90),
    MISSING_EXTENSION(109),
    UNSUPPORTED_EXTENSION(110),

    UNRECOGNIZED_NAME(112),

    BAD_CERTIFICATE_STATUS_RESPONSE(113),

    UNKNOWN_PSK_IDENTITY(115),

    CERTIFICATE_REQUIRED(116),
    NO_APPLICATION_PROTOCOL(120);

    private val value = value.toByte()

    fun value(): Byte {
        return value
    }
}

