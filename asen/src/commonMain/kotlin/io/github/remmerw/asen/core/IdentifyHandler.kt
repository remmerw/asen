package io.github.remmerw.asen.core

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.quic.Handler
import io.github.remmerw.asen.quic.Stream
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

internal data class IdentifyHandler(val peerId: PeerId) : Handler {


    @OptIn(ExperimentalSerializationApi::class)
    override fun protocol(stream: Stream) {

        val identify: Identify = identify(
            peerId, "asen/1.0.0/", stream.connection.responder().protocols.names()
        )
        stream.writeOutput(
            true,
            encode(ProtoBuf.encodeToByteArray(identify), MULTISTREAM_PROTOCOL, IDENTITY_PROTOCOL)
        )
    }


    override fun data(stream: Stream, data: ByteArray) {
        if (data.isNotEmpty()) {
            throw Exception("not expected data received for identify")
        }
    }
}
