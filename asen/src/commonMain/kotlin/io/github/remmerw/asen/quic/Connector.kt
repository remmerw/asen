package io.github.remmerw.asen.quic

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock


class Connector() {
    private val connections: MutableSet<ClientConnection> = mutableSetOf()
    private val mutex = Mutex()

    suspend fun connections(): Set<ClientConnection> {
        return mutex.withLock {
            connections.toSet()
        }
    }

    suspend fun shutdown() {
        mutex.withLock {
            connections.forEach { connection: ClientConnection -> connection.close() }
            connections.clear()
        }
    }

    suspend fun addConnection(connection: ClientConnection) {
        require(connection.isConnected) { "Connection not connected" }
        mutex.withLock {
            connections.add(connection)
        }
    }

    suspend fun removeConnection(connection: ClientConnection) {
        mutex.withLock {
            connections.remove(connection)
        }
    }
}
