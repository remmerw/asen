package io.github.remmerw.asen.quic

import kotlinx.atomicfu.locks.reentrantLock
import kotlinx.atomicfu.locks.withLock


class Connector(private val reserve: (Any) -> Unit) {
    private val connections: MutableSet<ClientConnection> = mutableSetOf()
    private val lock = reentrantLock()

    fun connections(): Set<ClientConnection> {
        return lock.withLock {
            connections.toSet()
        }
    }

    fun shutdown() {
        lock.withLock {
            connections.forEach { connection: ClientConnection -> connection.close() }
            connections.clear()
        }
    }

    fun addConnection(connection: ClientConnection) {
        require(connection.isConnected) { "Connection not connected" }
        lock.withLock {
            connections.add(connection)
        }
    }

    fun removeConnection(connection: ClientConnection) {
        lock.withLock {
            connections.remove(connection)
        }
        if (connection.isMarked()) {
            reserve.invoke(Any())
        }
    }
}
