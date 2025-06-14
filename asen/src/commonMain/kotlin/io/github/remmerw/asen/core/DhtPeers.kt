package io.github.remmerw.asen.core

import kotlinx.atomicfu.locks.reentrantLock
import kotlinx.atomicfu.locks.withLock

internal class DhtPeers(val saturation: Int) {
    private val peerSet: MutableSet<DhtPeer> = mutableSetOf()
    private val lock = reentrantLock()


    internal fun nextPeer(): DhtPeer? {
        return lock.withLock {
            val value = peerSet.minOrNull()
            if (value != null) {
                peerSet.remove(value)
            }
            value
        }
    }

    internal fun add(dhtPeer: DhtPeer): Boolean {
        return lock.withLock {
            if (peerSet.add(dhtPeer)) {
                if (peerSet.size >= saturation) {
                    val last = peerSet.maxOf { it }
                    peerSet.remove(last)
                    last !== dhtPeer // pointer comparison
                } else {
                    true
                }
            } else {
                false
            }
        }
    }

    internal fun first(): DhtPeer {
        return peerSet.minOf { it }
    }

    internal fun last(): DhtPeer {
        return peerSet.maxOf { it }
    }
}
