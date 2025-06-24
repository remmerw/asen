package io.github.remmerw.asen.quic

data class Responder(val protocols: Protocols) {
    suspend fun protocol(stream: Stream, protocol: String) {
        val handler = protocols.get(protocol)
        if (handler != null) {
            handler.protocol(stream)
        } else {
            stream.resetStream(Settings.PROTOCOL_NEGOTIATION_FAILED.toLong())
        }
    }


    suspend fun data(stream: Stream, protocol: String, data: ByteArray) {
        val handler = protocols.get(protocol)
        if (handler != null) {
            handler.data(stream, data)
        } else {
            stream.resetStream(Settings.PROTOCOL_NEGOTIATION_FAILED.toLong())
        }
    }


    internal fun createResponder(stream: Stream): AlpnResponder {
        return AlpnResponder(stream, this, Libp2pState(this))
    }
}