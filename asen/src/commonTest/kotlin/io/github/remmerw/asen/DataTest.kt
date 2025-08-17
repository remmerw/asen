package io.github.remmerw.asen

import io.github.remmerw.asen.core.OCTET_MIME_TYPE
import io.github.remmerw.asen.core.newStorage
import io.github.remmerw.asen.core.splitterSize
import io.github.remmerw.asen.core.tempFile
import kotlinx.io.buffered
import kotlinx.io.files.SystemFileSystem
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DataTest {

    @Test
    fun storeAndGetBlock() {
        val storage = newStorage()
        val maxSize = 50

        // prepare data
        val bytes = Random.nextBytes(maxSize)


        // (1) store data
        val raw = storage.storeData(bytes)

        // (2) get data
        val data = storage.fetchData(raw)
        assertContentEquals(bytes, data)

        // cleanup
        storage.deleteBlock(raw.cid)
        storage.delete()
    }

    @Test
    fun storeAndGetRaw() {
        val storage = newStorage()
        val maxSize = 50

        val random = Random
        val bytes = ByteArray(maxSize)
        random.nextBytes(bytes)

        // (1) store data
        val node = storage.storeData(bytes)

        // tests
        assertNotNull(node)
        assertEquals(node.size, maxSize.toLong())


        // (2) get data
        val data = storage.fetchData(node)
        assertEquals(data, bytes)
        storage.delete()
    }

    @Test
    fun storeAndGetFile() {
        val storage = newStorage()

        val temp = tempFile()
        val iteration = 10
        SystemFileSystem.sink(temp).buffered().use { source ->
            repeat(iteration) {
                source.write(Random.nextBytes(splitterSize()))
            }
        }
        // (1) store the file
        val node = storage.storeFile(temp, OCTET_MIME_TYPE)

        // tests
        assertNotNull(node)
        assertEquals(node.size, (iteration * splitterSize()).toLong())
        assertEquals(node.name, temp.name)
        assertEquals(node.mimeType, OCTET_MIME_TYPE)

        // (2) get the file
        val outputFile = tempFile()
        storage.transferTo(node, outputFile)

        // tests
        assertEquals(
            SystemFileSystem.metadataOrNull(outputFile)?.size,
            SystemFileSystem.metadataOrNull(temp)?.size
        )

        // cleanup
        SystemFileSystem.delete(outputFile)
        SystemFileSystem.delete(temp)
        storage.delete()
    }
}