package io.github.remmerw.asen.quic

internal interface ClientMessageSender {
    suspend fun send(clientHello: ClientHello)

    suspend fun send(finishedMessage: FinishedMessage)

    suspend fun send(certificateMessage: CertificateMessage)

    suspend fun send(certificateVerifyMessage: CertificateVerifyMessage)
}
