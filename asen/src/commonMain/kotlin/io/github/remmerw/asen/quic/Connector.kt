package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import io.github.remmerw.borr.PeerId
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread
import kotlin.math.min

interface Listener {
    fun removeConnection(connection: Connection)
}

class Connector : Listener {
    private val connections: MutableMap<InetSocketAddress, Connection> = ConcurrentHashMap()
    private val socket = DatagramSocket()


    private val receiver = thread(
        start = true,
        isDaemon = true,
        name = "Connector Receiver",
        priority = Thread.MAX_PRIORITY
    ) {
        runReceiver()
    }

    private val maintenance = thread(
        start = true,
        isDaemon = true,
        name = "Connector Maintenance",
        priority = Thread.MAX_PRIORITY
    ) {
        runMaintenance()
    }


    fun connections(): List<Connection> {
        return connections.values.filter { connection -> connection.isConnected }
    }

    private fun runMaintenance() {
        try {
            while (!Thread.interrupted()) {
                var delay = 1000
                connections.values.forEach { connection ->
                    try {
                        delay = min(delay, connection.maintenance())
                    } catch (throwable: Throwable) {
                        debug(throwable)
                    }
                }

                Thread.sleep(delay.toLong())
            }
        } catch (_: InterruptedException) {
        } catch (_: SocketException) {
        } catch (throwable: Throwable) {
            debug(throwable)
            shutdown()
        }
    }


    fun shutdown() {
        connections.values.forEach { connection: Connection -> connection.close() }
        connections.clear()

        try {
            receiver.interrupt()
        } catch (throwable: Throwable) {
            debug(throwable)
        }

        try {
            maintenance.interrupt()
        } catch (throwable: Throwable) {
            debug(throwable)
        }

        try {
            socket.close()
        } catch (throwable: Throwable) {
            debug(throwable)
        }
    }

    private fun runReceiver() {

        val data = ByteArray(Settings.MAX_PACKET_SIZE)

        try {
            while (!Thread.interrupted()) {
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
        } catch (_: InterruptedException) {
        } catch (_: SocketException) {
        } catch (throwable: Throwable) {
            debug(throwable)
            shutdown()
        }
    }


    override fun removeConnection(connection: Connection) {
        connections.remove(connection.remoteAddress())
    }

    fun connect(
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
            listener = this
        )
        connections[remoteAddress] = clientConnection
        clientConnection.connect(timeout)

        return clientConnection
    }
}
