package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import io.github.remmerw.borr.PeerId
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

interface Listener {
    fun removeConnection(connection: Connection)
}

class Connector() : Listener {
    private val connections: MutableMap<InetSocketAddress, Connection> = ConcurrentHashMap()
    private val socket = DatagramSocket()
    private val scope = CoroutineScope(Dispatchers.IO)

    init {
        scope.launch {
            runReceiver()
        }
    }

    fun connections(): List<Connection> {
        return connections.values.filter { connection -> connection.isConnected }
    }

    suspend fun shutdown() {
        connections.values.forEach { connection: Connection -> connection.close() }
        connections.clear()

        try {
            scope.cancel()
        } catch (throwable: Throwable) {
            debug(throwable)
        }

        try {
            socket.close()
        } catch (throwable: Throwable) {
            debug(throwable)
        }
    }

    private suspend fun runReceiver(): Unit = coroutineScope {

        val data = ByteArray(1500) // todo check

        try {
            while (isActive) {
                val receivedPacket = DatagramPacket(data, data.size)

                socket.receive(receivedPacket)

                val data = receivedPacket.data.copyOfRange(0, receivedPacket.length)
                try {
                    val remoteAddress = receivedPacket.socketAddress as InetSocketAddress
                    val connection = connections[remoteAddress]
                    if (connection != null) {
                        connection.process(data)
                    } else {
                        debug("Could not find connection $remoteAddress")
                    }
                } catch (throwable: Throwable) {
                    debug(throwable)
                }
            }
        } catch (_: Throwable) {
            shutdown()
        }
    }


    override fun removeConnection(connection: Connection) {
        connections.remove(connection.remoteAddress())
    }

    suspend fun connect(
        remotePeerId: PeerId,
        remoteAddress: InetSocketAddress,
        protocols: Protocols,
        certificate: Certificate,
        timeout: Int
    ): Connection {

        val connection = connections[remoteAddress]
        if (connection != null) {
            return connection
        }

        val responder = Responder(protocols)

        val clientConnection = ClientConnection(
            version = Version.V1,
            socket = socket,
            remotePeerId = remotePeerId,
            remoteAddress = remoteAddress,
            cipherSuites = listOf(CipherSuite.TLS_AES_128_GCM_SHA256),
            certificate = certificate,
            responder = responder,
            scope = scope,
            listener = this
        )
        connections.put(remoteAddress, clientConnection)
        clientConnection.connect(timeout)

        return clientConnection
    }
}
