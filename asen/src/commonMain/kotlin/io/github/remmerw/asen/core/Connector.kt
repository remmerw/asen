package io.github.remmerw.asen.core

import io.github.remmerw.asen.Asen
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.createInetSocketAddress
import io.github.remmerw.asen.quic.AlpnRequester
import io.github.remmerw.asen.quic.AlpnState
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.CipherSuite
import io.github.remmerw.asen.quic.ClientConnection
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.Connector
import io.github.remmerw.asen.quic.Protocols
import io.github.remmerw.asen.quic.RequestResponse
import io.github.remmerw.asen.quic.Requester
import io.github.remmerw.asen.quic.Responder
import io.github.remmerw.asen.quic.Stream
import io.github.remmerw.asen.quic.Version
import io.ktor.network.selector.SelectorManager


internal suspend fun connect(asen: Asen, peeraddr: Peeraddr): Connection {

    val protocols = Protocols()
    protocols.put(MULTISTREAM_PROTOCOL, StreamHandler())
    protocols.put(IDENTITY_PROTOCOL, IdentifyHandler(asen.peerId()))

    return connect(
        asen.selectorManager(),
        asen.connector(),
        protocols, asen.certificate(), peeraddr, TIMEOUT
    )
}


suspend fun connect(
    selectorManager: SelectorManager,
    connector: Connector,
    protocols: Protocols,
    certificate: Certificate,
    peeraddr: Peeraddr,
    timeout: Int
): Connection {

    val remoteAddress = createInetSocketAddress(
        peeraddr.address,
        peeraddr.port.toInt()
    )
    val remotePeerId = peeraddr.peerId
    val responder = Responder(protocols)

    val clientConnection = ClientConnection(
        version = Version.V1,
        selectorManager = selectorManager,
        remotePeerId = remotePeerId,
        remoteAddress = remoteAddress,
        cipherSuites = listOf(CipherSuite.TLS_AES_128_GCM_SHA256),
        certificate = certificate,
        responder = responder,
        connector = connector
    )

    clientConnection.connect(timeout)

    return clientConnection
}

suspend fun createStream(connection: Connection, requester: Requester): Stream {
    return connection.createStream({ stream: Stream ->
        AlpnRequester(stream, requester, AlpnState(requester))
    }, true)
}


suspend fun createStream(connection: Connection): Stream {
    return connection.createStream({ stream: Stream -> RequestResponse(stream) }, true)
}
