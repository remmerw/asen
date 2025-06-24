package io.github.remmerw.asen.quic

internal data class AlpnState(private val requester: Requester) : StreamState() {
    override suspend fun accept(stream: Stream, frame: ByteArray) {
        if (frame.size > 0L) {
            if (!isProtocol(frame)) {
                requester.data(stream, frame)
            }
        }
    }
}

internal data class Libp2pState(private val responder: Responder) : StreamState() {
    var protocol: String? = null

    override suspend fun accept(stream: Stream, frame: ByteArray) {
        if (frame.isNotEmpty()) {
            if (isProtocol(frame)) {
                protocol = frame.copyOfRange(0, frame.size - 1).decodeToString()
                responder.protocol(stream, protocol!!)
            } else {
                responder.data(stream, protocol!!, frame)
            }
        }
    }
}