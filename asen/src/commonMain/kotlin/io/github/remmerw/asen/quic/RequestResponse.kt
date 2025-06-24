package io.github.remmerw.asen.quic

import kotlinx.io.Buffer

internal data class RequestResponse(val stream: Stream) : StreamHandler {
    override fun terminated() {
    }

    override fun fin() {
    }

    override fun readFully(): Boolean {
        return true
    }

    override suspend fun data(data: Buffer) {
        throw IllegalStateException("should never be invoked")
    }
}