package io.github.remmerw.asen.quic

/**
 * Notifies state changes in the TLS layer.
 */
internal interface TlsStatusEventHandler {
    fun handshakeSecretsKnown()

    fun handshakeFinished()

    fun extensionsReceived(extensions: List<Extension>)
}

