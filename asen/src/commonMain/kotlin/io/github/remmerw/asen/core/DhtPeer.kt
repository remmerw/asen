package io.github.remmerw.asen.core

import dev.whyoleg.cryptography.bigint.BigInt
import io.github.remmerw.asen.Peeraddr

internal data class DhtPeer(
    val peeraddr: Peeraddr,
    val replaceable: Boolean,
    val distance: BigInt
) : Comparable<DhtPeer> {
    override fun compareTo(other: DhtPeer): Int {
        return distance.compareTo(other.distance)
    }
}
