package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.algorithms.ECDSA
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random

@Suppress("ArrayInDataClass")
internal data class ClientHello(
    val extensions: List<Extension>,
    val cipherSuites: Array<CipherSuite>,
    override val bytes: ByteArray
) :
    HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.CLIENT_HELLO

    companion object {
        private const val MAX_CLIENT_HELLO_SIZE = 3000
        private const val MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 2 + 2 + 2


        /**
         * Parses a ClientHello message from a byte stream.
         */
        fun parse(
            buffer: Buffer,
            customExtensionParser: ExtensionParser?,
            data: ByteArray
        ): ClientHello {
            if (buffer.size < 4) {
                throw DecodeErrorException("message underflow")
            }
            if (buffer.size < MINIMAL_MESSAGE_LENGTH - 1) {
                throw DecodeErrorException("message underflow")
            }


            val length = ((buffer.readByte().toInt() and 0xff) shl 16) or ((buffer.readByte()
                .toInt() and 0xff) shl 8) or (buffer.readByte().toInt() and 0xff)
            if (buffer.size < length) {
                throw DecodeErrorException("message underflow")
            }

            val legacyVersion = buffer.readShort().toInt()
            if (legacyVersion != 0x0303) {
                throw DecodeErrorException("legacy version must be 0303")
            }
            val cipherSuites: MutableList<CipherSuite> = arrayListOf()
            buffer.skip(32) // clientRandom


            val sessionIdLength = buffer.readByte().toInt()
            if (sessionIdLength > 0) {
                buffer.skip(sessionIdLength.toLong())
            }

            val cipherSuitesLength = buffer.readShort().toInt()
            var i = 0
            while (i < cipherSuitesLength) {
                val cipherSuiteValue = buffer.readShort()
                // https://tools.ietf.org/html/rfc8446#section-4.1.2
                // "If the list contains cipher suites that the server does not recognize, support, or wish to use,
                // the server MUST ignore those cipher suites and process the remaining ones as usual."
                val cipherSuite: CipherSuite? = CipherSuite.get(cipherSuiteValue)
                if (cipherSuite != null) cipherSuites.add(cipherSuite)
                i += 2
            }

            val legacyCompressionMethodsLength = buffer.readByte().toInt()
            val legacyCompressionMethod = buffer.readByte().toInt()
            if (legacyCompressionMethodsLength != 1 || legacyCompressionMethod != 0) {
                throw IllegalParameterAlert("Invalid legacy compression method")
            }


            val extensions = parseExtensions(
                buffer,
                HandshakeType.CLIENT_HELLO, customExtensionParser
            )
            if (extensions.any { ext: Extension? -> ext is PreSharedKeyExtension }) {
                // HandshakeMessage.findPositionLastExtension(buffer);
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
                // "The "pre_shared_key" extension MUST be the last extension in the ClientHello (...). Servers MUST check
                //  that it is the last extension and otherwise fail the handshake with an "illegal_parameter" alert."
                if (extensions[extensions.size - 1] !is PreSharedKeyExtension) {
                    throw IllegalParameterAlert("pre_shared_key extension MUST be the last extension in the ClientHello")
                }
            }

            return ClientHello(
                extensions, cipherSuites.toTypedArray(),
                data
            )
        }


        fun createClientHello(
            serverName: String?, publicKey: ECDSA.PublicKey,
            compatibilityMode: Boolean,
            supportedCiphers: List<CipherSuite>,
            supportedSignatures: List<SignatureScheme>,
            ecCurve: NamedGroup, extraExtensions: List<Extension>,
            pskKeyEstablishmentMode: PskKeyEstablishmentMode
        ): ClientHello {
            val buffer = Buffer()


            // client version
            buffer.writeByte(0x03.toByte())
            buffer.writeByte(0x03.toByte())

            // client random 32 bytes
            val clientRandom = CryptoRand.Default.nextBytes(ByteArray(32))
            buffer.write(clientRandom)

            val sessionId: ByteArray
            if (compatibilityMode) {
                sessionId = ByteArray(32)
                Random.nextBytes(sessionId)
            } else {
                sessionId = ByteArray(0)
            }
            buffer.writeByte(sessionId.size.toByte())
            if (sessionId.isNotEmpty()) buffer.write(sessionId)

            buffer.writeShort((supportedCiphers.size * 2).toShort())
            for (cipher in supportedCiphers) {
                buffer.writeShort(cipher.value)
            }

            // Compression
            // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
            // the "null" compression method in prior versions of TLS. "
            buffer.write(
                byteArrayOf(
                    0x01.toByte(), 0x00.toByte()
                )
            )

            val defaultExtensions = arrayOf(
                ServerNameExtension(serverName),
                SupportedVersionsExtension.createSupportedVersionsExtension(HandshakeType.CLIENT_HELLO),
                SupportedGroupsExtension.createSupportedGroupsExtension(ecCurve),
                SignatureAlgorithmsExtension(supportedSignatures),
                KeyShareExtension.create(publicKey, ecCurve, HandshakeType.CLIENT_HELLO),
            )

            val extensions: MutableList<Extension> = defaultExtensions.toMutableList()
            if (pskKeyEstablishmentMode != PskKeyEstablishmentMode.NONE) {
                extensions.add(createPskKeyExchangeModesExtension(pskKeyEstablishmentMode))
            }
            extensions.addAll(extraExtensions)


            val extensionsLength =
                extensions.sumOf { ext: Extension -> ext.getBytes().size }
            buffer.writeShort(extensionsLength.toShort())

            for (extension in extensions) {
                buffer.write(extension.getBytes())
            }

            val msg = Buffer()
            msg.writeByte(1.toByte()) // HandshakeType client_hello(1)
            msg.writeByte(0.toByte())
            msg.writeShort(buffer.size.toShort())
            msg.write(buffer, buffer.size)

            require(msg.size.toInt() < MAX_CLIENT_HELLO_SIZE)


            return ClientHello(extensions, supportedCiphers.toTypedArray(), msg.readByteArray())
        }

        private fun createPskKeyExchangeModesExtension(
            pskKeyEstablishmentMode: PskKeyEstablishmentMode
        ): PskKeyExchangeModesExtension {
            return when (pskKeyEstablishmentMode) {
                PskKeyEstablishmentMode.PSK_ONLY -> PskKeyExchangeModesExtension.createPskKeyExchangeModesExtension(
                    PskKeyExchangeMode.PSK_KE
                )

                PskKeyEstablishmentMode.PSK_DHE -> PskKeyExchangeModesExtension.createPskKeyExchangeModesExtension(
                    PskKeyExchangeMode.PSK_DHE_KE
                )

                PskKeyEstablishmentMode.BOTH -> PskKeyExchangeModesExtension.createPskKeyExchangeModesExtension(
                    arrayOf(
                        PskKeyExchangeMode.PSK_KE,
                        PskKeyExchangeMode.PSK_DHE_KE
                    )
                )

                else -> throw IllegalArgumentException()
            }
        }
    }


}
