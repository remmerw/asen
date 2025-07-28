package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import kotlinx.io.Buffer


internal data class AlpnRequester(
    val stream: Stream,
    val requester: Requester,
    val streamState: StreamState
) :
    StreamHandler {
    override fun data(data: Buffer) {
        try {
            StreamState.iteration(streamState, stream, data)
        } catch (exception: Exception) {
            stream.resetStream(Settings.PROTOCOL_NEGOTIATION_FAILED.toLong())
            throwable(exception)
        } catch (throwable: Throwable) {
            stream.resetStream(Settings.INTERNAL_ERROR.toLong())
            throwable(throwable)
        }
    }

    override fun terminated() {
        streamState.reset()
        requester.done()
    }

    override fun fin() {
        streamState.reset()
        requester.done()
    }

    fun throwable(throwable: Throwable) {
        debug("Error alpn requester" + throwable.message)
        streamState.reset()
        requester.done()
    }

    override fun readFully(): Boolean {
        return false
    }

}
