package io.github.remmerw.asen.quic

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDH
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.macs.hmac.sha2.HmacSHA256
import kotlin.math.ceil
import kotlin.math.min


internal class TlsState(
    private val privateKey: ECDH.PrivateKey,
    private val transcriptHash: TranscriptHash
) {

    // https://tools.ietf.org/html/rfc8446#section-7.1
    // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
    private val emptyHash: ByteArray = CryptographyProvider.Default
        .get(SHA256)
        .hasher()
        .hashBlocking(ByteArray(0))

    // https://tools.ietf.org/html/rfc8446#section-7.1
    // "If a given secret is not available, then the 0-value consisting of a
    //   string of Hash.length bytes set to zeros is used."
    private val psk = ByteArray(HASH_LENGTH.toInt())

    private var pskSelected = false
    private var serverSharedKey: ECDH.PublicKey? = null
    private lateinit var earlySecret: ByteArray
    lateinit var serverHandshakeTrafficSecret: ByteArray
        private set
    lateinit var clientHandshakeTrafficSecret: ByteArray
        private set
    private lateinit var handshakeSecret: ByteArray
    lateinit var clientApplicationTrafficSecret: ByteArray
        private set
    lateinit var serverApplicationTrafficSecret: ByteArray
        private set
    private lateinit var sharedSecret: ByteArray

    init {

        computeEarlySecret(psk)
    }


    private fun computeEarlySecret(ikm: ByteArray) {
        val zeroSalt = ByteArray(HASH_LENGTH.toInt())
        earlySecret = extractHmac(zeroSalt, ikm)
    }

    fun computeSharedSecret() {
        // Generate shared secret
        sharedSecret = privateKey.sharedSecretGenerator()
            .generateSharedSecretToByteArrayBlocking(serverSharedKey!!)

    }

    fun computeEarlyTrafficSecret() {
        val clientHelloHash = transcriptHash.getHash(HandshakeType.CLIENT_HELLO)

        hkdfExpandLabel(earlySecret, "c e traffic", clientHelloHash, HASH_LENGTH)
    }


    fun computeHandshakeSecrets() {
        val derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, HASH_LENGTH)

        handshakeSecret = extractHmac(derivedSecret, sharedSecret)

        val handshakeHash = transcriptHash.getHash(HandshakeType.SERVER_HELLO)

        clientHandshakeTrafficSecret = hkdfExpandLabel(
            handshakeSecret, "c hs traffic",
            handshakeHash, HASH_LENGTH
        )

        serverHandshakeTrafficSecret = hkdfExpandLabel(
            handshakeSecret, "s hs traffic",
            handshakeHash, HASH_LENGTH
        )
    }


    fun computeApplicationSecrets() {
        computeApplicationSecrets(handshakeSecret)
    }


    private fun computeApplicationSecrets(handshakeSecret: ByteArray) {
        val serverFinishedHash = transcriptHash.getServerHash(HandshakeType.FINISHED)

        val derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", emptyHash, HASH_LENGTH)
        val zeroKey = ByteArray(HASH_LENGTH.toInt())
        val masterSecret = extractHmac(derivedSecret, zeroKey)
        clientApplicationTrafficSecret = hkdfExpandLabel(
            masterSecret, "c ap traffic",
            serverFinishedHash, HASH_LENGTH
        )
        serverApplicationTrafficSecret = hkdfExpandLabel(
            masterSecret, "s ap traffic",
            serverFinishedHash, HASH_LENGTH
        )
    }


    fun hkdfExpandLabel(
        secret: ByteArray,
        label: String,
        context: String,
        length: Short
    ): ByteArray {
        //return hkdfExpandLabel(secret, label, context.toByteArray(Charsets.ISO_8859_1), length)
        return hkdfExpandLabel(secret, label, context.encodeToByteArray(), length)
    }

    private fun hkdfExpandLabel(
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Short
    ): ByteArray {
        val content = label.encodeToByteArray()
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        val size = 2 + 1 + LABEL_PREFIX.length + content.size + 1 + context.size
        val hkdfLabel = Buffer()
        hkdfLabel.writeShort(length)
        hkdfLabel.writeByte((LABEL_PREFIX.length + content.size).toByte())
        hkdfLabel.write(LABEL_PREFIX.encodeToByteArray())
        hkdfLabel.write(label.encodeToByteArray())
        hkdfLabel.writeByte((context.size).toByte())
        hkdfLabel.write(context)
        require(size == hkdfLabel.size.toInt())

        return expandHmac(secret, hkdfLabel.readByteArray(), length.toInt())
    }


    fun setPskSelected() {
        pskSelected = true
    }

    fun setNoPskSelected() {
        if (!pskSelected) {
            // Recompute early secret, as psk is not accepted by server.
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "... if no PSK is selected, it will then need to compute the Early Secret corresponding to the zero PSK."
            computeEarlySecret(ByteArray(HASH_LENGTH.toInt()))
        }
    }

    fun setPeerKey(serverSharedKey: ECDSA.PublicKey) {
        val ecdh = CryptographyProvider.Default.get(ECDH)

        this.serverSharedKey = ecdh.publicKeyDecoder(EC.Curve.P256)
            .decodeFromByteArrayBlocking(
                EC.PublicKey.Format.RAW,
                serverSharedKey.encodeToByteArrayBlocking(EC.PublicKey.Format.RAW)
            )
    }

    companion object {


        fun expandHmac(secret: ByteArray, input: ByteArray?, length: Int): ByteArray {
            var info = input
            try {
                val mac = HmacSHA256(secret)

                if (info == null) {
                    info = ByteArray(0)
                }

                /*
                The output OKM is calculated as follows:
                  N = ceil(L/HashLen)
                  T = T(1) | T(2) | T(3) | ... | T(N)
                  OKM = first L bytes of T
                where:
                  T(0) = empty string (zero length)
                  T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
                  T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
                  T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
                  ...
                 */
                var blockN = ByteArray(0)

                val iterations = ceil((length.toDouble()) / (mac.macLength().toDouble())).toInt()

                require(iterations <= 255) {
                    ("out length must be maximal 255 * hash-length; requested: "
                            + length + " bytes")
                }

                val buffer = Buffer()
                var remainingBytes = length
                var stepSize: Int

                for (i in 0 until iterations) {
                    mac.update(blockN)
                    mac.update(info)
                    mac.update((i + 1).toByte())

                    blockN = mac.doFinal()

                    stepSize = min(remainingBytes, blockN.size)

                    buffer.write(blockN, 0, stepSize)
                    remainingBytes -= stepSize
                }
                require(buffer.size.toInt() == length)
                return buffer.readByteArray()
            } catch (throwable: Throwable) {
                throw BadRecordMacAlert(throwable.message)
            }
        }

        private fun extractHmac(salt: ByteArray, info: ByteArray): ByteArray {
            try {
                val mac = HmacSHA256(salt)
                require(info.isNotEmpty()) {
                    "provided info must be at least of size 1 and not null"
                }
                return mac.doFinal(info)
            } catch (throwable: Throwable) {
                throw BadRecordMacAlert(throwable.message)
            }
        }
    }
}
