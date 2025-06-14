package io.github.remmerw.asen.quic


import at.asitplus.signum.indispensable.pki.X509Certificate
import dev.whyoleg.cryptography.algorithms.ECDSA


data class Certificate(
    val x509: X509Certificate,
    val publicKey: ECDSA.PublicKey,
    val privateKey: ECDSA.PrivateKey,
    val scheme: SignatureScheme
)