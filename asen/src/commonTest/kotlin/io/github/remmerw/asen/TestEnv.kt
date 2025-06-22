package io.github.remmerw.asen

import kotlin.random.Random


internal object TestEnv {
    const val ITERATIONS: Int = 4096

    fun randomPeerId(): PeerId {
        return PeerId(getRandomBytes(32))
    }

    fun getRandomBytes(number: Int): ByteArray {
        val bytes = ByteArray(number)
        Random.nextBytes(bytes)
        return bytes
    }

}
