package io.github.remmerw.asen.core

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class DhtPeers(val saturation: Int) {
    private val peerSet: MutableSet<DhtPeer> = mutableSetOf()
    private val mutex = Mutex()


    internal suspend fun nextPeer(): DhtPeer? {
        return mutex.withLock {
            val value = peerSet.minOrNull()
            if (value != null) {
                peerSet.remove(value)
            }
            value
        }
    }

    internal suspend fun add(dhtPeer: DhtPeer): Boolean {
        return mutex.withLock {
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
