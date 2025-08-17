package io.github.remmerw.asen

import io.github.remmerw.asen.core.decodeNode
import io.github.remmerw.asen.core.encodeRaw
import io.github.remmerw.asen.core.newStorage
import kotlinx.coroutines.runBlocking
import kotlinx.io.Buffer
import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

class CatTest {
    @Test
    fun catNotExist(): Unit = runBlocking {
        val cid = abs(Random.nextLong())
        val storage = newStorage()
        try {
            val buffer = Buffer()
            storage.transferBlock(buffer, cid)
            fail()

        } catch (_: Exception) {
            // ignore
        } finally {
            storage.delete()
        }

    }


    @Test
    fun catLocalTest(): Unit = runBlocking {
        val storage = newStorage()
        val local = storage.storeText("Moin Moin Moin")
        assertNotNull(local)
        val content = storage.fetchData(local)
        assertNotNull(content)

        val buffer = encodeRaw(content)

        val node = decodeNode(local.cid, buffer)
        assertNotNull(node)
        assertEquals(node.cid, local.cid)
        storage.delete()
    }
}