package io.github.remmerw.asen.quic

import kotlinx.io.Buffer

internal fun interface ExtensionParser {

    fun apply(
        buffer: Buffer,
        type: Int,
        length: Int,
        handshakeType: HandshakeType
    ): Extension?
}

