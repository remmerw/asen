package io.github.remmerw.asen.core

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.SocketAddress
import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.debug
import io.github.remmerw.asen.multihash
import io.github.remmerw.asen.parseAddress
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.Requester
import io.github.remmerw.asen.quic.Stream
import io.github.remmerw.asen.verify
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

@Suppress("ArrayInDataClass")
internal data class SignatureMessage(val bytes: ByteArray)

internal data class ConnectRequest(
    val target: PeerId,
    val signatureMessage: SignatureMessage,
    val done: Semaphore,
) : Requester {
    private val result = mutableListOf<SocketAddress>()

    fun result(): List<SocketAddress> {
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
            val addresses = decodeMessage(target, data)
            result.addAll(addresses)
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
            stream.mark(target)
        }

    }


    suspend fun initializeConnect(stream: Stream) {
        stream.writeOutput(
            true,
            encodeMessage(
                signatureMessage
            )
        )
    }
}


@OptIn(ExperimentalSerializationApi::class)
internal suspend fun connectHop(
    connection: Connection,
    target: PeerId,
    signatureMessage: SignatureMessage
): List<SocketAddress>? {

    val done = Semaphore(1, 1)

    val hopMessage = HopMessage(
        HopMessage.Type.CONNECT,
        Peer(multihash(target))
    )

    val message = ProtoBuf.encodeToByteArray<HopMessage>(hopMessage)

    val request = ConnectRequest(target, signatureMessage, done)
    createStream(
        connection, request
    ).writeOutput(
        false,
        encode(
            message, MULTISTREAM_PROTOCOL, RELAY_PROTOCOL_HOP
        )
    )

    return withTimeoutOrNull(TIMEOUT * 1000L) {
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


internal fun relayMessage(signature: ByteArray, addresses: List<SocketAddress>): SignatureMessage {
    require(addresses.size <= Byte.MAX_VALUE) { "to many peeraddrs" }

    var size = Byte.SIZE_BYTES


    val encodedAddresses = ArrayList<ByteArray>(addresses.size)
    for (address in addresses) {
        val encoded = address.encoded()
        encodedAddresses.add(encoded)
        size += unsignedVariantSize(encoded.size.toLong()) + encoded.size
    }

    size += unsignedVariantSize(signature.size.toLong()) + signature.size

    val dataLength = unsignedVariantSize(size.toLong())

    val buffer = Buffer()
    writeUnsignedVariant(buffer, size.toLong())
    buffer.writeByte(addresses.size.toByte())


    for (encoded in encodedAddresses) {
        writeUnsignedVariant(buffer, encoded.size.toLong())
        buffer.write(encoded)
    }

    writeUnsignedVariant(buffer, signature.size.toLong())
    buffer.write(signature)

    require(buffer.size == (dataLength.toLong() + size)) { "Still data to write" }

    return SignatureMessage(buffer.readByteArray())
}

internal fun encodeMessage(signatureMessage: SignatureMessage): Buffer {
    val buffer = Buffer()
    buffer.write(signatureMessage.bytes)
    return buffer
}


@OptIn(ExperimentalCoroutinesApi::class)
internal fun CoroutineScope.hopRequest(
    target: PeerId,
    signatureMessage: SignatureMessage,
    channel: ReceiveChannel<Connection>
): ReceiveChannel<List<SocketAddress>> = produce {

    channel.consumeEach { connection ->
        val handled: MutableSet<PeerId> = mutableSetOf()

        try {
            if (handled.add(connection.remotePeerId())) {
                val addresses =
                    connectHop(connection, target, signatureMessage)
                if (!addresses.isNullOrEmpty()) {
                    send(addresses)
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        } finally {
            connection.close()
        }
    }
}


fun decodeMessage(peerId: PeerId, data: ByteArray): List<SocketAddress> {
    val buffer = Buffer()
    buffer.write(data)

    val toVerify = Buffer()
    val size = buffer.readByte()
    val addresses = mutableListOf<SocketAddress>()

    repeat(size.toInt()) {
        val length = readUnsignedVariant(buffer)
        val raw = buffer.readByteArray(length)
        toVerify.write(raw)
        val sa = parseAddress(raw)
        if (sa != null) {
            addresses.add(sa)
        }
    }

    val sigSize = readUnsignedVariant(buffer)
    val signature = buffer.readByteArray(sigSize)

    verify(peerId, toVerify.readByteArray(), signature)

    require(buffer.exhausted()) { "still data available" }

    return addresses
}
