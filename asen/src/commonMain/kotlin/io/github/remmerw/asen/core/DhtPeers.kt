package io.github.remmerw.asen.core

import io.ktor.util.collections.ConcurrentSet

internal class DhtPeers(val saturation: Int) {
    private val peerSet: MutableSet<DhtPeer> = ConcurrentSet()


    internal fun nextPeer(): DhtPeer? {

        val value = first()
        if (value != null) {
            peerSet.remove(value)
        }
        return value
    }

    internal fun add(dhtPeer: DhtPeer): Boolean {
        if (peerSet.add(dhtPeer)) {
            if (peerSet.size >= saturation) {
                val last = last()
                peerSet.remove(last)
                return last !== dhtPeer // pointer comparison
            } else {
                return true
            }
        } else {
            return false
        }

    }

    internal fun first(): DhtPeer? {
        return peerSet.minOrNull()
    }

    internal fun last(): DhtPeer? {
        return peerSet.maxOrNull()
    }
}
