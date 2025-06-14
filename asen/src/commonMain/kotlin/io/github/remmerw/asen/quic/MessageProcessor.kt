package io.github.remmerw.asen.quic


internal interface Message

internal interface MessageProcessor : Message {

    fun received(clientHello: ClientHello)

    fun received(serverHello: ServerHello)

    fun received(
        encryptedExtensions: EncryptedExtensions,
        protectionKeysType: ProtectionKeysType
    )

    fun received(
        certificateMessage: CertificateMessage,
        protectionKeysType: ProtectionKeysType
    )

    fun received(
        certificateVerifyMessage: CertificateVerifyMessage,
        protectionKeysType: ProtectionKeysType
    )

    fun received(
        finishedMessage: FinishedMessage,
        protectionKeysType: ProtectionKeysType
    )

    fun received(
        certificateRequestMessage: CertificateRequestMessage,
        protectionKeysType: ProtectionKeysType
    )
}
