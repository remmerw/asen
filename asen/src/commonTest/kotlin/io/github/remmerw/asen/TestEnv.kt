package io.github.remmerw.asen

import io.github.remmerw.borr.PeerId
import kotlin.random.Random


internal object TestEnv {
    const val ITERATIONS: Int = 4096

    fun longRunningTestsEnabled(): Boolean {
        return false
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
