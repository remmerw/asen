package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.time.measureTime

class ObservedTest {

    @Test
    fun observedAddress(): Unit = runBlocking(Dispatchers.IO) {

        val duration = measureTime {
            val server = newAsen()
            val address = server.observedAddress()
            assertNotNull(address)

            val peeraddr = Peeraddr(server.peerId(), address, 1234.toUShort())
            assertNotNull(peeraddr)

            if (peeraddr.inet4()) {
                println("Warning onl IPv4 address")
            }
            server.shutdown()
        }
        println("Time public addressed " + duration.inWholeMilliseconds + " [ms]")
    }
}