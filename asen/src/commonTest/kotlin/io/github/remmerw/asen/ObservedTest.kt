package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.measureTime

class ObservedTest {

    @Test
    fun observedAddress(): Unit = runBlocking(Dispatchers.IO) {

        val duration = measureTime {
            val server = newAsen()

            val addresses = server.observedAddresses()
            assertTrue(addresses.isNotEmpty())

            addresses.forEach { entry ->
                val peeraddr = Peeraddr(
                    server.peerId(), entry.address,
                    1234.toUShort()
                )
                assertNotNull(peeraddr)
            }

            server.shutdown()
        }
        println("Time public addressed " + duration.inWholeMilliseconds + " [ms]")
    }
}