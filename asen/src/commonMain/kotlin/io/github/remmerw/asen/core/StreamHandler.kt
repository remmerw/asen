package io.github.remmerw.asen.core

import io.github.remmerw.asen.quic.Handler
import io.github.remmerw.asen.quic.Stream

internal class StreamHandler : Handler {
    override suspend fun protocol(stream: Stream) {
        // nothing to do here
    }


    override suspend fun data(stream: Stream, data: ByteArray) {
        if (data.isNotEmpty()) {
            throw Exception("not expected data received for multistream")
        }
    }
}