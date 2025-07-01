package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.measureTime

class PublicAddress {

    @Test
    fun publicAddress(): Unit = runBlocking(Dispatchers.IO) {

        val duration = measureTime {
            val server = newAsen()
            val address = server.publicAddress()
            assertNotNull(address)

            val peeraddr = Peeraddr(server.peerId(), address, 1234.toUShort())
            assertNotNull(peeraddr)

            assertTrue(peeraddr.inet6())
            assertFalse(peeraddr.inet4())

            server.shutdown()
        }
        println("Time public addressed " + duration.inWholeMilliseconds + " [ms]")
    }
}