package io.github.remmerw.asen.quic


import dev.whyoleg.cryptography.algorithms.ECDSA


data class Certificate(
    val x509: io.github.remmerw.asen.cert.Certificate,
    val publicKey: ECDSA.PublicKey,
    val privateKey: ECDSA.PrivateKey,
    val scheme: SignatureScheme
)