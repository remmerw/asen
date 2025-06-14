package io.github.remmerw.asen.core

@Suppress("ArrayInDataClass")
data class Key(val hash: ByteArray, val target: ByteArray) {
    init {
        require(hash.size == 32) { "hash size must be 32" }
    }
}