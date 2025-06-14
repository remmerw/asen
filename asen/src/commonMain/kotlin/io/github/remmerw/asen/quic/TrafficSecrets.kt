package io.github.remmerw.asen.quic

internal interface TrafficSecrets {
    val clientHandshakeTrafficSecret: ByteArray

    val serverHandshakeTrafficSecret: ByteArray

    val clientApplicationTrafficSecret: ByteArray

    val serverApplicationTrafficSecret: ByteArray
}
