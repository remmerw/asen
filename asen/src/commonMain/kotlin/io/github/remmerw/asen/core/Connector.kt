package io.github.remmerw.asen.core

import io.github.remmerw.asen.Asen
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.quic.AlpnRequester
import io.github.remmerw.asen.quic.AlpnState
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.Protocols
import io.github.remmerw.asen.quic.RequestResponse
import io.github.remmerw.asen.quic.Requester
import io.github.remmerw.asen.quic.Stream


internal fun connect(asen: Asen, peeraddr: Peeraddr): Connection {

    val protocols = Protocols()
    protocols.put(MULTISTREAM_PROTOCOL, StreamHandler())
    protocols.put(IDENTITY_PROTOCOL, IdentifyHandler(asen.peerId()))

    return asen.connector().connect(
        remotePeerId = peeraddr.peerId,
        remoteAddress = peeraddr.toInetSocketAddress(),
        protocols = protocols,
        certificate = asen.certificate(),
        timeout = TIMEOUT
    )
}


fun createStream(connection: Connection, requester: Requester): Stream {
    return connection.createStream({ stream: Stream ->
        AlpnRequester(stream, requester, AlpnState(requester))
    }, true)
}

fun createStream(connection: Connection): Stream {
    return connection.createStream({ stream: Stream -> RequestResponse(stream) }, true)
}
