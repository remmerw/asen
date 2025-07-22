package io.github.remmerw.asen.quic

import java.util.concurrent.ConcurrentHashMap


class Connector() {
    private val connections: MutableSet<ClientConnection> = ConcurrentHashMap.newKeySet()


    fun connections(): Set<ClientConnection> {
        return connections.toSet()
    }

    suspend fun shutdown() {
        connections.forEach { connection: ClientConnection -> connection.close() }
        connections.clear()

    }

    fun addConnection(connection: ClientConnection) {
        require(connection.isConnected) { "Connection not connected" }
        connections.add(connection)

    }

    fun removeConnection(connection: ClientConnection) {
        connections.remove(connection)
    }
}
