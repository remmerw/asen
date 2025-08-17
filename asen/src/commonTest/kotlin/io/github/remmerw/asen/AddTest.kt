package io.github.remmerw.asen

import io.github.remmerw.asen.core.OCTET_MIME_TYPE
import io.github.remmerw.asen.core.newStorage
import io.github.remmerw.asen.core.splitterSize
import kotlinx.coroutines.runBlocking
import kotlinx.io.Buffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AddTest {


    @Test
    fun add_and_remove(): Unit = runBlocking {
        assertFailsWith<Exception> {
            val storage = newStorage()
            val content = "Hello cat"
            val node = storage.storeText(content)
            assertEquals(content.encodeToByteArray().size, node.size.toInt())


            assertTrue(storage.hasBlock(node.cid))

            val text = node.cid

            assertTrue(storage.hasBlock(text))
            storage.delete(node)
            assertFalse(storage.hasBlock(text))

            try {
                val buffer = Buffer()
                storage.transferBlock(buffer, node.cid) // closed exception expected
            } finally {
                storage.delete()
            }
        }
    }


    @Test
    fun create_text() {
        val storage = newStorage()
        val content1 = "Pa gen fichye ki make pou efase"
        val text1 = TestEnv.createContent(
            storage, "Pa gen fichye ki make pou efase.txt",
            "text/plain", content1.encodeToByteArray()
        )
        assertNotNull(text1)

        val content2 = "Non pa valab"
        val text2 = TestEnv.createContent(
            storage, "Non pa valab.txt",
            "text/plain",
            content2.encodeToByteArray()
        )
        assertNotNull(text2)
        storage.delete()
    }

    @Test
    fun add_wrap(): Unit = runBlocking {
        val storage = newStorage()
        val packetSize = 1000
        val maxData = 1000
        val fid = TestEnv.createContent(
            storage, "test.bin", OCTET_MIME_TYPE,
            Random.nextBytes(maxData * packetSize)
        )

        assertNotNull(fid)
        assertTrue(fid.name.isNotEmpty())

        val bytes = storage.readByteArray(fid)
        assertEquals(bytes.size.toLong(), fid.size)
        storage.delete()
    }


    @Test
    fun add(): Unit = runBlocking {
        val packetSize = 1000
        val maxData = 1000

        val storage = newStorage()
        val fid = TestEnv.createContent(
            storage, "test.bin", OCTET_MIME_TYPE,
            Random.nextBytes(maxData * packetSize)
        )


        assertNotNull(fid)
        assertEquals(fid.mimeType, OCTET_MIME_TYPE)

        val bytes = storage.readByteArray(fid)
        assertEquals(fid.size, bytes.size.toLong())

        storage.delete()
    }


    @Test
    fun add_wrap_small(): Unit = runBlocking {
        val packetSize = 200
        val maxData = 1000

        val storage = newStorage()
        val fid = TestEnv.createContent(
            storage, "test.bin", OCTET_MIME_TYPE,
            Random.nextBytes(maxData * packetSize)
        )


        val bytes = storage.readByteArray(fid)
        assertEquals(fid.size, bytes.size.toLong())

        storage.delete()
    }

    @Test
    fun createFile(): Unit = runBlocking {
        val packetSize = 200
        val maxData = 1000

        val storage = newStorage()
        val fid = TestEnv.createContent(
            storage, "test.bin", OCTET_MIME_TYPE,
            Random.nextBytes(maxData * packetSize)
        )


        val bytes = storage.readByteArray(fid)
        assertEquals(bytes.size.toLong(), fid.size)
        storage.delete()
    }


    @Test
    fun test_inputStream(): Unit = runBlocking {
        val storage = newStorage()
        val text = "moin zehn"
        val node = storage.storeText(text)
        assertTrue(storage.hasBlock(node.cid))

        val bytes = storage.fetchData(node)
        assertNotNull(bytes)
        assertEquals(bytes.size, text.length)
        assertEquals(text, bytes.decodeToString())
        storage.delete()
    }


    @Test
    fun test_inputStreamBig(): Unit = runBlocking {
        val storage = newStorage()
        val text = Random.nextBytes((splitterSize() * 2) - 50)
        val fid = TestEnv.createContent(storage, "random.bin", OCTET_MIME_TYPE, text)
        assertTrue(text.contentEquals(storage.readByteArray(fid)))
        storage.delete()
    }


    @Test
    fun createRawText(): Unit = runBlocking {
        val storage = newStorage()

        val name = "Домашняя страница"
        val node = storage.storeText(name)
        assertNotNull(node)

        assertEquals(storage.fetchText(node), name)
        storage.delete()
    }


}