package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

@Suppress("ArrayInDataClass")
internal data class ServerHello(
    val cipherSuite: CipherSuite,
    val extensions: List<Extension>,
    override val bytes: ByteArray
) : HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.SERVER_HELLO


    companion object {
        private const val MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2


        fun parse(buffer: Buffer, data: ByteArray): ServerHello {
            if (buffer.size < MINIMAL_MESSAGE_LENGTH - 1) {
                throw DecodeErrorException("Message too short")
            }

            buffer.skip(3) //  3 bytes length

            val versionHigh = buffer.readByte().toInt()
            val versionLow = buffer.readByte().toInt()
            if (versionHigh != 3 || versionLow != 3) throw IllegalParameterAlert("Invalid version number (should be 0x0303)")

            buffer.skip(32) // random


            val sessionIdLength = buffer.readByte().toInt() and 0xff
            if (sessionIdLength > 32) {
                throw DecodeErrorException("session id length exceeds 32")
            }
            buffer.readByteArray(sessionIdLength)  // must match, see 4.1.3 legacySessionIdEcho

            val cipherSuiteCode = buffer.readShort()

            // https://tools.ietf.org/html/rfc8446#section-4.1.2
            // "If the list contains cipher suites that the server does not recognize, support, or wish to use,
            // the server MUST ignore those cipher suites and process the remaining ones as usual."
            val cipherSuite: CipherSuite =
                CipherSuite.get(cipherSuiteCode)
                    ?: throw DecodeErrorException("Unknown cipher suite ($cipherSuiteCode)")

            val legacyCompressionMethod = buffer.readByte().toInt()
            if (legacyCompressionMethod != 0) {
                // https://www.davidwong.fr/tls13/#section-4.1.3
                // "legacy_compression_method: A single byte which MUST have the value 0."
                throw DecodeErrorException("Legacy compression method must have the value 0")
            }

            val extensions = parseExtensions(buffer, HandshakeType.SERVER_HELLO)

            return ServerHello(cipherSuite, extensions, data)
        }
    }
}
