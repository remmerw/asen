package io.github.remmerw.asen.core

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.multihash
import io.github.remmerw.asen.parsePeeraddr
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.Requester
import io.github.remmerw.asen.quic.Stream
import io.github.remmerw.asen.verify
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withTimeout
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

@Suppress("ArrayInDataClass")
internal data class RelayMessage(val bytes: ByteArray)

internal data class ConnectRequest(
    val target: PeerId,
    val relayMessage: RelayMessage,
    val done: Semaphore,
) : Requester {
    private val result = mutableListOf<Peeraddr>()

    fun result(): List<Peeraddr> {
        return result.toList()
    }

    override fun done() {
        try {
            done.release()
        } catch (_: Throwable) {
        }
    }


    @OptIn(ExperimentalSerializationApi::class)
    override suspend fun data(stream: Stream, data: ByteArray) {

        if (stream.isMarked()) {
            val syncInfo = decodeMessage(target, data)
            result.addAll(syncInfo)
            done.release()
        } else {

            val msg = ProtoBuf.decodeFromByteArray<HopMessage>(data)
            checkNotNull(msg)

            if (msg.type != HopMessage.Type.STATUS) {
                done()
                stream.close()
                return
            }

            if (msg.status != Status.OK) {
                done()
                stream.close()
                return
            }

            initializeConnect(stream)
            stream.mark()
        }

    }


    suspend fun initializeConnect(stream: Stream) {
        stream.writeOutput(
            true,
            encodeMessage(
                relayMessage
            )
        )
    }
}


@OptIn(ExperimentalSerializationApi::class)
internal suspend fun connectHop(
    connection: Connection,
    target: PeerId,
    relayMessage: RelayMessage
): List<Peeraddr> {

    val done = Semaphore(1, 1)

    val hopMessage = HopMessage(
        HopMessage.Type.CONNECT,
        Peer(multihash(target))
    )

    val message = ProtoBuf.encodeToByteArray<HopMessage>(hopMessage)

    val request = ConnectRequest(target, relayMessage, done)
    createStream(
        connection, request
    ).writeOutput(
        false,
        encode(
            message, MULTISTREAM_PROTOCOL, RELAY_PROTOCOL_HOP
        )
    )

    return withTimeout(TIMEOUT * 1000L) {
        done.acquire()
        request.result()
    }

}


@OptIn(ExperimentalSerializationApi::class)
internal suspend fun reserveHop(connection: Connection, self: PeerId) {

    val hopMessage = HopMessage(
        type = HopMessage.Type.RESERVE,
        peer = Peer(multihash(self))
    )

    val message = ProtoBuf.encodeToByteArray<HopMessage>(hopMessage)

    val data = createStream(connection).request(
        TIMEOUT.toLong(), encode(
            message, MULTISTREAM_PROTOCOL,
            RELAY_PROTOCOL_HOP
        )
    )

    val response = receiveResponse(data)
    if (response.isNotEmpty()) {

        val msg = ProtoBuf.decodeFromByteArray<HopMessage>(response)
        checkNotNull(msg)

        if (msg.type != HopMessage.Type.STATUS) {
            error("NO RESERVATION STATUS")
        }
        if (msg.status != Status.OK) {
            error("RESERVATION STATUS = " + msg.status)
        }
        if (msg.reservation == null) {
            error("NO RESERVATION")
        }
        val reserve = msg.reservation
        checkNotNull(reserve)
        return

    }
    error("No Hop Service")
}


internal fun relayMessage(signature: ByteArray, peeraddrs: List<Peeraddr>): RelayMessage {
    require(peeraddrs.size <= Byte.MAX_VALUE) { "to many peeraddrs" }

    var size = Byte.SIZE_BYTES

    val checkIfValid: MutableSet<PeerId> = mutableSetOf()

    val encodedAddresses = ArrayList<ByteArray>(peeraddrs.size)
    for (peeraddr in peeraddrs) {
        checkIfValid.add(peeraddr.peerId)
        val encoded = peeraddr.encoded()
        encodedAddresses.add(encoded)
        size += unsignedVariantSize(encoded.size.toLong()) + encoded.size
    }

    // only addresses of the same peerId
    require(checkIfValid.size <= 1) { "Invalid usage" }


    size += unsignedVariantSize(signature.size.toLong()) + signature.size

    val dataLength = unsignedVariantSize(size.toLong())

    val buffer = Buffer()
    writeUnsignedVariant(buffer, size.toLong())
    buffer.writeByte(peeraddrs.size.toByte())


    for (encoded in encodedAddresses) {
        writeUnsignedVariant(buffer, encoded.size.toLong())
        buffer.write(encoded)
    }

    writeUnsignedVariant(buffer, signature.size.toLong())
    buffer.write(signature)

    require(buffer.size == (dataLength.toLong() + size)) { "Still data to write" }

    return RelayMessage(buffer.readByteArray())
}

internal fun encodeMessage(relayMessage: RelayMessage): Buffer {
    val buffer = Buffer()
    buffer.write(relayMessage.bytes)
    return buffer
}

private fun decodeMessage(peerId: PeerId, data: ByteArray): List<Peeraddr> {
    val buffer = Buffer()
    buffer.write(data)

    var toVerify = BYTES_EMPTY
    val size = buffer.readByte()
    val peeraddrs = mutableListOf<Peeraddr>()

    repeat(size.toInt()) {
        val length = readUnsignedVariant(buffer)
        val raw = buffer.readByteArray(length)
        toVerify = concat(toVerify, raw)
        peeraddrs.add(parsePeeraddr(peerId, raw))
    }

    val sigSize = readUnsignedVariant(buffer)
    val signature = buffer.readByteArray(sigSize)

    verify(peerId, toVerify, signature)

    require(buffer.exhausted()) { "still data available" }

    return peeraddrs
}
