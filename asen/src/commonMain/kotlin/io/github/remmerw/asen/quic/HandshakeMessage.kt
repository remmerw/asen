package io.github.remmerw.asen.quic


internal interface HandshakeMessage {
    val type: HandshakeType
    val bytes: ByteArray
}
