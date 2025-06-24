package io.github.remmerw.asen.quic

/**
 * Notifies state changes in the TLS layer.
 */
internal interface TlsStatusEventHandler {
    fun handshakeSecretsKnown()

    suspend fun handshakeFinished()

    suspend fun extensionsReceived(extensions: List<Extension>)
}

