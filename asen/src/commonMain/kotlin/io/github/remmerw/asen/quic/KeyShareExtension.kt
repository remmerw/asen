package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * The TLS "key_share" extension contains the endpoint's cryptographic parameters.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.8)
 */
@Suppress("ArrayInDataClass")
internal data class KeyShareExtension(
    val handshakeType: HandshakeType,
    val keyShareEntries: Array<KeyShareEntry>
) : Extension {
    override fun getBytes(): ByteArray {
        val keyShareEntryLength =
            keyShareEntries
                .map { obj: KeyShareEntry -> obj.namedGroup() }
                .map { o: NamedGroup -> CURVE_KEY_LENGTHS[o]!! }.sumOf { s: Int -> 2 + 2 + s }
                .toShort()
        var extensionLength = keyShareEntryLength
        if (handshakeType == HandshakeType.CLIENT_HELLO) {
            extensionLength = (extensionLength + 2).toShort()
        }

        val buffer = Buffer()

        buffer.writeShort(ExtensionType.KEY_SHARE.value)
        buffer.writeShort(extensionLength) // Extension data length (in bytes)

        if (handshakeType == HandshakeType.CLIENT_HELLO) {
            buffer.writeShort(keyShareEntryLength)
        }

        for (keyShare in keyShareEntries) {
            buffer.writeShort(keyShare.namedGroup().value)
            buffer.writeShort(getCurveKeyLength(keyShare.namedGroup()))
            // See https://tools.ietf.org/html/rfc8446#section-4.2.8.2,
            // "For secp256r1, secp384r1, and secp521r1, ..."
            if (keyShare.namedGroup() == NamedGroup.SECP256r1) {
                buffer.write(
                    keyShare.key().encodeToByteArrayBlocking(
                        EC.PublicKey.Format.RAW
                    )
                )
            } else {
                throw RuntimeException("not supported")
            }
        }
        require(buffer.size.toInt() == 4 + extensionLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.KEY_SHARE
    }


    interface KeyShareEntry {
        fun namedGroup(): NamedGroup

        fun key(): ECDSA.PublicKey
    }


    private data class BasicKeyShareEntry(
        val namedGroup: NamedGroup,
        val key: ECDSA.PublicKey
    ) : KeyShareEntry {
        override fun namedGroup(): NamedGroup {
            return namedGroup
        }

        override fun key(): ECDSA.PublicKey {
            return key
        }
    }


    private data class ECKeyShareEntry(
        val namedGroup: NamedGroup,
        val key: ECDSA.PublicKey
    ) : KeyShareEntry {
        override fun namedGroup(): NamedGroup {
            return namedGroup
        }

        override fun key(): ECDSA.PublicKey {
            return key
        }
    }

    companion object {
        private val supportedCurves: List<NamedGroup> = listOf(NamedGroup.SECP256r1)
        private val CURVE_KEY_LENGTHS: Map<NamedGroup, Int> = mapOf(
            NamedGroup.SECP256r1 to 65
        )


        fun create(
            publicKey: ECDSA.PublicKey,
            ecCurve: NamedGroup,
            handshakeType: HandshakeType
        ): KeyShareExtension {
            if (!supportedCurves.contains(ecCurve)) {
                throw RuntimeException("Only curves supported: $supportedCurves")
            }
            val keyShareEntries = arrayOf<KeyShareEntry>(BasicKeyShareEntry(ecCurve, publicKey))
            return KeyShareExtension(handshakeType, keyShareEntries)
        }

        private fun createKeyShareExtension(
            buffer: Buffer, extensionLength: Int,
            handshakeType: HandshakeType
        ): KeyShareExtension {
            val keyShareEntries: MutableList<KeyShareEntry> = arrayListOf()

            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 1
            )
            if (extensionDataLength < 2) {
                throw DecodeErrorException("extension underflow")
            }

            if (handshakeType == HandshakeType.CLIENT_HELLO) {
                val keyShareEntriesSize = buffer.readShort().toInt()
                if (extensionDataLength != 2 + keyShareEntriesSize) {
                    throw DecodeErrorException("inconsistent length")
                }
                var remaining = keyShareEntriesSize
                while (remaining > 0) {
                    remaining -= parseKeyShareEntry(keyShareEntries, buffer)
                }
                if (remaining != 0) {
                    throw DecodeErrorException("inconsistent length")
                }
            } else if (handshakeType == HandshakeType.SERVER_HELLO) {
                var remaining = extensionDataLength
                remaining -= parseKeyShareEntry(keyShareEntries, buffer)
                if (remaining != 0) {
                    throw DecodeErrorException("inconsistent length")
                }
            } else {
                throw IllegalArgumentException()
            }

            return KeyShareExtension(
                handshakeType,
                keyShareEntries.toTypedArray()
            )
        }

        /**
         * Assuming KeyShareServerHello:
         * "In a ServerHello message, the "extension_data" field of this
         * extension contains a KeyShareServerHello value..."
         */
        fun create(
            buffer: Buffer,
            extensionLength: Int,
            handshakeType: HandshakeType
        ): KeyShareExtension {
            return createKeyShareExtension(buffer, extensionLength, handshakeType)
        }

        private fun getCurveKeyLength(namedGroup: NamedGroup): Short {
            val length = CURVE_KEY_LENGTHS[namedGroup]
                ?: throw NullPointerException()
            return length.toShort()
        }

        private fun rawToEncodedECPublicKey(rawBytes: ByteArray): ECDSA.PublicKey {
            val ecdsa = CryptographyProvider.Default.get(ECDSA)
            return ecdsa.publicKeyDecoder(EC.Curve.P256)
                .decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW, rawBytes)
        }


        private fun parseKeyShareEntry(
            keyShareEntries: MutableList<KeyShareEntry>,
            buffer: Buffer
        ): Int {
            var read = 0
            if (buffer.size < 4) {
                throw DecodeErrorException("extension underflow")
            }

            val namedGroupValue = buffer.readShort()
            read += 2
            val namedGroup: NamedGroup = NamedGroup.get(namedGroupValue)

            if (!supportedCurves.contains(namedGroup)) {
                throw RuntimeException("Curve '$namedGroup' not supported")
            }

            val keyLength = buffer.readShort().toInt()
            read += 2
            if (buffer.size < keyLength) {
                throw DecodeErrorException("extension underflow")
            }
            if (keyLength != getCurveKeyLength(namedGroup).toInt()) {
                throw DecodeErrorException("Invalid " + namedGroup.name + " key length: " + keyLength)
            }

            read += keyLength

            val keyData = buffer.readByteArray(keyLength)
            val ecPublicKey = rawToEncodedECPublicKey(keyData)
            keyShareEntries.add(ECKeyShareEntry(namedGroup, ecPublicKey))

            return read
        }
    }
}
