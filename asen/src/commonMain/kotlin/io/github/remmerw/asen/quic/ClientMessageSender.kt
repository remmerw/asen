package io.github.remmerw.asen.quic

internal interface ClientMessageSender {
    fun send(clientHello: ClientHello)

    fun send(finishedMessage: FinishedMessage)

    fun send(certificateMessage: CertificateMessage)

    fun send(certificateVerifyMessage: CertificateVerifyMessage)
}
