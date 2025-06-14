package io.github.remmerw.asen

import kotlin.random.Random


internal object TestEnv {
    const val ITERATIONS: Int = 4096
    val BOOTSTRAP: MutableList<Peeraddr> = mutableListOf()

    init {
        try {
            // "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
            val address = byteArrayOf(104.toByte(), 131.toByte(), 131.toByte(), 82.toByte())
            BOOTSTRAP.add(
                createPeeraddr(
                    "QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", address, 4001.toUShort()
                )
            )
        } catch (throwable: Throwable) {
            error(throwable)
        }
    }


    fun randomPeerId(): PeerId {
        return PeerId(getRandomBytes(32))
    }

    fun getRandomBytes(number: Int): ByteArray {
        val bytes = ByteArray(number)
        Random.nextBytes(bytes)
        return bytes
    }

}
