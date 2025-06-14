package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug


// https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1
internal class TransportError(errorCode: Code) : Exception(errorCode.name) {
    private val errorCode = errorCode.value().toLong()

    init {
        if (this.errorCode != 0L) {
            debug("TransportError " + errorCode.name)
        }
    }

    fun errorCode(): Long {
        return errorCode
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-error-codes
    @Suppress("unused")
    enum class Code(value: Int) {
        NO_ERROR(0x0),
        INTERNAL_ERROR(0x1),

        CONNECTION_REFUSED(0x2),

        FLOW_CONTROL_ERROR(0x3),
        STREAM_LIMIT_ERROR(0x4),
        STREAM_STATE_ERROR(0x5),

        FINAL_SIZE_ERROR(0x6),
        FRAME_ENCODING_ERROR(0x7),
        TRANSPORT_PARAMETER_ERROR(0x8),
        CONNECTION_ID_LIMIT_ERROR(0x9),
        PROTOCOL_VIOLATION(0xa),

        INVALID_TOKEN(0xb),

        APPLICATION_ERROR(0xc),

        CRYPTO_BUFFER_EXCEEDED(0xd),

        KEY_UPDATE_ERROR(0xe),

        AEAD_LIMIT_REACHED(0xf),

        NO_VIABLE_PATH(0x10),

        CRYPTO_ERROR(0x100),

        // https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-08.html#iana-error
        VERSION_NEGOTIATION_ERROR(0x53F8); // !! When this document is approved, it will request permanent allocation of a codepoint in the 0-63 range to replace the provisional codepoint described above.


        private val value = value.toShort()

        fun value(): Short {
            return value
        }
    }
}
