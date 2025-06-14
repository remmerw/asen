package io.github.remmerw.asen.quic

import at.asitplus.signum.indispensable.pki.X509Certificate
import dev.whyoleg.cryptography.algorithms.ECDSA
import org.kotlincrypto.macs.hmac.sha2.HmacSHA256

abstract class TlsEngine(val publicKey: ECDSA.PublicKey, val privateKey: ECDSA.PrivateKey) :
    MessageProcessor, TrafficSecrets {
    internal var state: TlsState? = null
    var remoteCertificate: X509Certificate? = null


    // https://tools.ietf.org/html/rfc8446#section-4.4.4

    fun computeFinishedVerifyData(transcriptHash: ByteArray, baseKey: ByteArray): ByteArray {
        val hashLength: Short = HASH_LENGTH
        val finishedKey = state!!.hkdfExpandLabel(baseKey, "finished", "", hashLength)

        val hmacAlgorithm = HmacSHA256(finishedKey)
        hmacAlgorithm.update(transcriptHash)
        return hmacAlgorithm.doFinal()

    }

    override val clientHandshakeTrafficSecret: ByteArray
        get() {
            if (state != null) {
                return state!!.clientHandshakeTrafficSecret
            } else {
                throw IllegalStateException("Traffic secret not yet available")
            }
        }

    override val serverHandshakeTrafficSecret: ByteArray
        get() {
            if (state != null) {
                return state!!.serverHandshakeTrafficSecret
            } else {
                throw IllegalStateException("Traffic secret not yet available")
            }
        }

    override val clientApplicationTrafficSecret: ByteArray
        get() {
            if (state != null) {
                return state!!.clientApplicationTrafficSecret
            } else {
                throw IllegalStateException("Traffic secret not yet available")
            }
        }

    override val serverApplicationTrafficSecret: ByteArray
        get() {
            if (state != null) {
                return state!!.serverApplicationTrafficSecret
            } else {
                throw IllegalStateException("Traffic secret not yet available")
            }
        }

}

