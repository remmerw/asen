package io.github.remmerw.asen

import io.github.remmerw.asen.core.Node
import io.github.remmerw.asen.core.OCTET_MIME_TYPE
import io.github.remmerw.asen.core.Storage
import io.github.remmerw.asen.core.splitterSize
import io.github.remmerw.asen.core.tempFile
import io.github.remmerw.borr.PeerId
import kotlinx.io.buffered
import kotlinx.io.files.SystemFileSystem
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


    fun createContent(storage: Storage, name: String, data: ByteArray): Node {
        val temp = tempFile(name)
        SystemFileSystem.sink(temp).buffered().use { source ->
            source.write(data)
        }

        val node = storage.storeFile(temp, OCTET_MIME_TYPE)

        SystemFileSystem.delete(temp)
        return node
    }

    fun createContent(storage: Storage, iteration: Int): Node {
        val temp = tempFile()
        SystemFileSystem.sink(temp).buffered().use { source ->
            repeat(iteration) {
                source.write(Random.nextBytes(splitterSize()))
            }
        }

        val node = storage.storeFile(temp, OCTET_MIME_TYPE)

        SystemFileSystem.delete(temp)
        return node
    }

    fun createContent(
        storage: Storage,
        name: String,
        mimeType: String,
        data: ByteArray
    ): Node {
        val temp = tempFile(name)
        SystemFileSystem.sink(temp).buffered().use { source ->
            source.write(data)
        }

        val node = storage.storeFile(temp, mimeType)

        SystemFileSystem.delete(temp)
        return node

    }

}
