package io.github.remmerw.asen.core


import io.github.remmerw.asen.Asen
import io.github.remmerw.asen.DHT_ALPHA
import io.github.remmerw.asen.DHT_CONCURRENCY
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.quic.Connection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

private const val DHT_PEER_SET_MAX_SIZE = 100
private fun evalClosestPeers(pms: Message, peers: DhtPeers, key: Key): List<DhtPeer> {
    val dhtPeers: MutableList<DhtPeer> = arrayListOf()
    for (entry in pms.closerPeers) {
        if (entry.addrs.isNotEmpty()) {
            val reachable = reachablePeeraddr(
                entry.id, entry.addrs
            )

            if (reachable != null) {
                val dhtPeer: DhtPeer = createDhtPeer(reachable, true, key)
                val result = peers.add(dhtPeer)
                if (result) {
                    dhtPeers.add(dhtPeer)
                }
            }
        }
    }
    return dhtPeers
}


private suspend fun bootstrap(asen: Asen, key: Key): List<DhtPeer> {
    val peers: MutableList<DhtPeer> = arrayListOf()

    val peeraddrs = asen.bootstrap()
    for (peeraddr in peeraddrs) {
        peers.add(createDhtPeer(peeraddr, false, key))
    }

    val stored = asen.peerStore().peeraddrs(DHT_ALPHA)

    for (peeraddr in stored) {
        peers.add(createDhtPeer(peeraddr, true, key))
    }

    return peers
}


internal suspend fun findClosestPeers(
    scope: CoroutineScope,
    channel: Channel<Connection>,
    asen: Asen,
    key: Key
) {
    val message = createFindNodeMessage(key)
    val peers = initialPeers(asen, key)
    runRequest(scope, channel, asen, key, peers, message)
}


private suspend fun request(
    asen: Asen, dhtPeer: DhtPeer,
    message: Message, channel: Channel<Connection>
): Message {
    val connection = connect(asen, dhtPeer.peeraddr)
    val msg = request(connection, message)

    if (dhtPeer.replaceable) {
        channel.send(connection)
    }
    return msg
}


private suspend fun initialPeers(asen: Asen, key: Key): DhtPeers {

    val dhtPeers = DhtPeers(DHT_PEER_SET_MAX_SIZE)
    val pds = bootstrap(asen, key)

    for (dhtPeer in pds) {
        dhtPeers.add(dhtPeer)
    }
    return dhtPeers
}


private fun runRequest(
    scope: CoroutineScope,
    channel: Channel<Connection>,
    asen: Asen, key: Key,
    dhtPeers: DhtPeers, message: Message
) {

    val done: MutableSet<Peeraddr> = mutableSetOf()
    val semaphore = Semaphore(DHT_CONCURRENCY)
    do {
        val nextPeer = dhtPeers.nextPeer()

        val hasPeer = nextPeer != null
        if (hasPeer) {
            if (done.add(nextPeer.peeraddr)) {
                scope.launch {
                    semaphore.withPermit {
                        try {
                            val pms = request(asen, nextPeer, message, channel)

                            val res = evalClosestPeers(pms, dhtPeers, key)
                            if (res.isNotEmpty()) {
                                if (nextPeer.replaceable) {
                                    asen.peerStore().store(nextPeer.peeraddr)
                                }
                            }
                        } catch (_: Throwable) {
                            // ignore exceptions
                        }
                    }
                }
            }
        }
    } while (scope.isActive)

    channel.close() // finish the channel is important here
}

internal fun createDhtPeer(peeraddr: Peeraddr, replaceable: Boolean, key: Key): DhtPeer {
    val peerKey = createPeerIdKey(peeraddr.peerId)
    val distance = keyDistance(key, peerKey)
    return DhtPeer(peeraddr, replaceable, distance)
}


private fun createFindNodeMessage(key: Key): Message {
    return Message(
        type = Message.MessageType.FIND_NODE,
        key = key.target
    )
}


@OptIn(ExperimentalSerializationApi::class)
private suspend fun request(connection: Connection, message: Message): Message {
    val msg = ProtoBuf.encodeToByteArray<Message>(message)
    val data = createStream(connection)
        .request(
            TIMEOUT.toLong(), encode(
                msg, MULTISTREAM_PROTOCOL, DHT_PROTOCOL
            )
        )
    val response = receiveResponse(data)
    return ProtoBuf.decodeFromByteArray<Message>(response)
}

