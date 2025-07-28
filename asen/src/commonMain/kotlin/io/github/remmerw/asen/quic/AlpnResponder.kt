package io.github.remmerw.asen.quic

import kotlinx.io.Buffer


internal data class AlpnResponder(
    val stream: Stream,
    val responder: Responder,
    val streamState: Libp2pState
) : StreamHandler {
    override fun data(data: Buffer) {
        try {
            StreamState.iteration(streamState, stream, data)
        } catch (_: Exception) {
            stream.resetStream(Settings.PROTOCOL_NEGOTIATION_FAILED.toLong())
        } catch (_: Throwable) {
            stream.resetStream(Settings.INTERNAL_ERROR.toLong())
        }
    }

    override fun terminated() {
        streamState.reset()
    }

    override fun fin() {
        streamState.reset()
    }

    override fun readFully(): Boolean {
        return false
    }
}

