package io.github.remmerw.asen.core

import io.github.remmerw.asen.Asen
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.TIMEOUT
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
import io.ktor.network.sockets.InetSocketAddress


internal suspend fun connect(asen: Asen, address: Peeraddr): Connection {

    val protocols = Protocols()
    protocols.put(MULTISTREAM_PROTOCOL, StreamHandler())
    protocols.put(IDENTITY_PROTOCOL, IdentifyHandler(asen.peerId()))

    return connect(asen.connector(), protocols, asen.certificate(), address, TIMEOUT)
}


suspend fun connect(
    connector: Connector,
    protocols: Protocols,
    certificate: Certificate,
    address: Peeraddr,
    timeout: Int
): Connection {

    val remoteAddress = InetSocketAddress(address.address(), address.port.toInt())

    val responder = Responder(protocols)

    val clientConnection = ClientConnection(
        Version.V1, address, remoteAddress,
        listOf(CipherSuite.TLS_AES_128_GCM_SHA256), certificate,
        responder, connector
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
