package io.github.remmerw.asen.quic

import io.ktor.util.collections.ConcurrentSet


class Connector() {
    private val connections: MutableSet<ClientConnection> = ConcurrentSet()


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
