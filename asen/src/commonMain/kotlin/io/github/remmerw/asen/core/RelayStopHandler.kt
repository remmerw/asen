package io.github.remmerw.asen.core

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.debug
import io.github.remmerw.asen.parsePeerId
import io.github.remmerw.asen.quic.Handler
import io.github.remmerw.asen.quic.Stream
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

internal data class RelayStopHandler(
    private val self: PeerId,
    private val signatureMessage: SignatureMessage
) :
    Handler {
    override suspend fun protocol(stream: Stream) {
        stream.writeOutput(
            false, encode(
                MULTISTREAM_PROTOCOL,
                RELAY_PROTOCOL_STOP
            )
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    override suspend fun data(stream: Stream, data: ByteArray) {

        if (stream.isMarked()) {

            stream.writeOutput(
                true,
                encodeMessage(signatureMessage)
            )

        } else {
            try {
                val msg = ProtoBuf.decodeFromByteArray<StopMessage>(data)
                checkNotNull(msg)


                if (msg.type != StopMessage.Type.CONNECT) {
                    createStatusMessage(stream, Status.MALFORMED_MESSAGE)
                    return
                }
                if (msg.peer == null) {
                    createStatusMessage(stream, Status.MALFORMED_MESSAGE)
                    return
                }
                val peer = msg.peer

                val peerId = parsePeerId(peer.id)

                if (peerId == null) {
                    createStatusMessage(stream, Status.MALFORMED_MESSAGE)
                    return
                }

                if (peerId == self) {
                    createStatusMessage(stream, Status.PERMISSION_DENIED)
                    return
                }

                val stopMessage = StopMessage(
                    StopMessage.Type.STATUS,
                    status = Status.OK
                )

                val message = ProtoBuf.encodeToByteArray<StopMessage>(stopMessage)

                stream.writeOutput(false, encode(message))
                stream.mark()
            } catch (throwable: Throwable) {
                debug(throwable)
                createStatusMessage(stream, Status.UNEXPECTED_MESSAGE)
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    private suspend fun createStatusMessage(stream: Stream, status: Status) {
        val stopMessage = StopMessage(
            StopMessage.Type.STATUS,
            status = status
        )

        val message = ProtoBuf.encodeToByteArray<StopMessage>(stopMessage)
        stream.writeOutput(true, encode(message))
    }

}
