package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.AES.ECB
import dev.whyoleg.cryptography.operations.Cipher
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

internal data class Keys(
    val writerKey: ByteArray, val writeIV: ByteArray, val hp: ByteArray,
    val trafficSecret: ByteArray, val keyPhaseCounter: Int
) {
    val keyPhase: Short
        get() = (keyPhaseCounter % 2).toShort()

    /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded). This function will return true, when update is required.
     */
    fun checkKeyPhase(keyPhaseBit: Short): Boolean {
        return (keyPhaseCounter % 2) != keyPhaseBit.toInt()
    }

    @OptIn(DelicateCryptographyApi::class)
    fun aeadEncrypt(associatedData: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        try {
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
            // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
            // https://tools.ietf.org/html/rfc5116#section-5.3: "the tag length t is 16"

            val aesGcm = CryptographyProvider.Default.get(AES.GCM)
            val key = aesGcm.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, writerKey)
            val cipher = key.cipher()
            return cipher.encryptWithIvBlocking(iv, plaintext, associatedData)
        } catch (throwable: Throwable) {
            throw IllegalStateException(throwable)
        }
    }

    @OptIn(DelicateCryptographyApi::class)
    fun aeadDecrypt(associatedData: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        if (ciphertext.size <= 16) {
            // https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
            // "These cipher suites have a 16-byte authentication tag and produce an output 16
            // bytes larger than their ciphertext."
            throw DecryptErrorAlert("ciphertext must be longer than 16 bytes")
        }
        try {
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
            // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
            // https://tools.ietf.org/html/rfc5116#section-5.3: "the tag length t is 16"
            val aesGcm = CryptographyProvider.Default.get(AES.GCM)
            val key = aesGcm.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, writerKey)
            val cipher = key.cipher()
            return cipher.decryptWithIvBlocking(iv, ciphertext, associatedData)

        } catch (throwable: Throwable) {
            throw DecryptErrorAlert(throwable.message)
        }
    }

    fun createHeaderProtectionMask(sample: ByteArray): ByteArray {
        return getHeaderProtectionCipher(hp).encryptBlocking(sample)
    }


    override fun hashCode(): Int {
        var result = writerKey.contentHashCode()
        result = 31 * result + writeIV.contentHashCode()
        result = 31 * result + hp.contentHashCode()
        result = 31 * result + trafficSecret.contentHashCode()
        result = 31 * result + keyPhaseCounter
        return result
    }

    companion object {
        private const val KEY_LENGTH: Short = 16

        fun createInitialKeys(version: Int, initialSecret: ByteArray, client: Boolean): Keys {
            try {
                val initialNodeSecret = hkdfExpandLabel(
                    initialSecret,
                    if (client) "client in" else "server in",
                    32.toShort()
                )

                return computeKeys(version, initialNodeSecret)
            } catch (throwable: Throwable) {
                throw IllegalStateException(throwable)
            }
        }

        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        private fun hkdfExpandLabel(
            secret: ByteArray,
            label: String,
            length: Short
        ): ByteArray {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1:
            // "The keys used for packet protection are computed from the TLS secrets using the KDF provided by TLS."
            val prefix =
                "tls13 ".encodeToByteArray()

            val size = 2 + 1 + prefix.size +
                    label.encodeToByteArray().size + 1 +
                    "".encodeToByteArray().size
            val hkdfLabel = Buffer()
            hkdfLabel.writeShort(length)
            hkdfLabel.writeByte((prefix.size + label.encodeToByteArray().size).toByte())
            hkdfLabel.write(prefix)
            hkdfLabel.write(label.encodeToByteArray())
            hkdfLabel.writeByte(("".encodeToByteArray().size).toByte())
            hkdfLabel.write("".encodeToByteArray())

            require(hkdfLabel.size == size.toLong()) { "Invalid size" }
            return TlsState.expandHmac(secret, hkdfLabel.readByteArray(), length.toInt())
        }


        fun computeKeyUpdate(version: Int, keys: Keys): Keys {
            var prefix: String
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The current encryption level secret and the label "quic key" are
            //   input to the KDF to produce the AEAD key; the label "quic iv" is used
            //   to derive the IV, see Section 5.3.  The header protection key uses
            //   the "quic hp" label, see Section 5.4).  Using these labels provides
            //   key separation between QUIC and TLS, see Section 9.4."
            prefix = "quic "
            if (Version.isV2(version)) {
                // https://www.ietf.org/archive/id/draft-ietf-quic-v2-01.html#name-long-header-packet-types
                // "The labels used in [QUIC-TLS] to derive packet protection keys (Section 5.1), header protection keys (Section 5.4),
                //  Retry Integrity Tag keys (Section 5.8), and key updates (Section 6.1) change from "quic key" to "quicv2 key",
                //  from "quic iv" to "quicv2 iv", from "quic hp" to "quicv2 hp", and from "quic ku" to "quicv2 ku", to meet
                //  the guidance for new versions in Section 9.6 of that document."
                prefix = "quicv2 "
            }
            try {
                val trafficSecret =
                    hkdfExpandLabel(keys.trafficSecret, prefix + "ku", 32.toShort())

                val writeKey = hkdfExpandLabel(trafficSecret, prefix + "key", KEY_LENGTH)

                val writeIV = hkdfExpandLabel(trafficSecret, prefix + "iv", 12.toShort())

                return Keys(writeKey, writeIV, keys.hp, trafficSecret, (keys.keyPhaseCounter + 1))
            } catch (throwable: Throwable) {
                throw IllegalStateException(throwable)
            }
        }

        fun computeHandshakeKeys(version: Int, client: Boolean, secrets: TrafficSecrets): Keys {
            return if (client) {
                computeKeys(
                    version,
                    secrets.clientHandshakeTrafficSecret
                )
            } else {
                computeKeys(
                    version,
                    secrets.serverHandshakeTrafficSecret
                )
            }
        }

        fun computeApplicationKeys(version: Int, client: Boolean, secrets: TrafficSecrets): Keys {
            return if (client) {
                computeKeys(
                    version,
                    secrets.clientApplicationTrafficSecret
                )
            } else {
                computeKeys(
                    version,
                    secrets.serverApplicationTrafficSecret
                )
            }
        }


        private fun computeKeys(version: Int, trafficSecret: ByteArray): Keys {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The current encryption level secret and the label "quic key" are
            //   input to the KDF to produce the AEAD key; the label "quic iv" is used
            //   to derive the IV, see Section 5.3.  The header protection key uses
            //   the "quic hp" label, see Section 5.4).  Using these labels provides
            //   key separation between QUIC and TLS, see Section 9.4."


            var prefix = "quic "
            if (Version.isV2(version)) {
                // https://www.ietf.org/archive/id/draft-ietf-quic-v2-01.html#name-long-header-packet-types
                // "The labels used in [QUIC-TLS] to derive packet protection keys (Section 5.1), header protection keys (Section 5.4),
                //  Retry Integrity Tag keys (Section 5.8), and key updates (Section 6.1) change from "quic key" to "quicv2 key",
                //  from "quic iv" to "quicv2 iv", from "quic hp" to "quicv2 hp", and from "quic ku" to "quicv2 ku", to meet
                //  the guidance for new versions in Section 9.6 of that document."
                prefix = "quicv2 "
            }


            // https://tools.ietf.org/html/rfc8446#section-7.3
            val writeKey = hkdfExpandLabel(trafficSecret, prefix + "key", KEY_LENGTH)

            val writeIV = hkdfExpandLabel(trafficSecret, prefix + "iv", 12.toShort())

            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The header protection key uses the "quic hp" label"
            val hp = hkdfExpandLabel(trafficSecret, prefix + "hp", KEY_LENGTH)

            return Keys(writeKey, writeIV, hp, trafficSecret, 0)

        }

        @OptIn(DelicateCryptographyApi::class)
        private fun getHeaderProtectionCipher(hp: ByteArray): Cipher {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.3
            // "AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES [AES] in electronic code-book
            // (ECB) mode."

            val aesEcb = CryptographyProvider.Default.get(ECB)
            val key = aesEcb.keyDecoder().decodeFromByteArrayBlocking(AES.Key.Format.RAW, hp)
            return key.cipher()

        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Keys

        if (keyPhaseCounter != other.keyPhaseCounter) return false
        if (!writerKey.contentEquals(other.writerKey)) return false
        if (!writeIV.contentEquals(other.writeIV)) return false
        if (!hp.contentEquals(other.hp)) return false
        if (!trafficSecret.contentEquals(other.trafficSecret)) return false
        if (keyPhase != other.keyPhase) return false

        return true
    }
}
