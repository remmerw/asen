package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertTrue

class LongTermTest {


    @Test
    fun longRunningTest(): Unit = runBlocking(Dispatchers.IO) {

        if (!TestEnv.longRunningTestsEnabled()) {
            println("Long running tests disabled")
            return@runBlocking
        }

        val server = newAsen()

        val addresses = server.observedAddresses()
        assertTrue(addresses.isNotEmpty(), "Observer Addresses not defined")

        // Use Case : alice wants to connect to bob
        // [1] bob has to make reservations to relays
        val serverAddresses = addresses.map { address ->
            InetSocketAddress(address, 5555) // 5555 bob server
        }

        server.makeReservations(
            serverAddresses,
            100,
            120
        )


        repeat(40) {
            println("Reservations " + server.numReservations())
            delay(1000 * 30) // 30 sec break

        }

        server.shutdown()
    }
}