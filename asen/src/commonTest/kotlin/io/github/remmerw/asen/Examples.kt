package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Examples {

    @Test
    fun resolveAddresses(): Unit = runBlocking(Dispatchers.IO) {

        val bob = newAsen()
        val alice = newAsen()

        val observerAddresses = bob.observedAddresses()
        assertTrue(observerAddresses.isNotEmpty(), "Observer Addresses not defined")

        // Use Case : alice wants to connect to bob
        // [1] bob has to make reservations to relays
        val publicAddresses = observerAddresses.map { address ->
            SocketAddress(address.bytes, 5001.toUShort())
        }

        // Note: bob has a service running on port 5001
        bob.makeReservations(
            publicAddresses,
            20,
            120
        )  // timeout max 2 min (120 s) or 20 relays

        println("Reservations " + bob.numReservations())

        assertTrue(bob.hasReservations())

        // [2] alice can find bob addresses via its peerId
        val peeraddrs = alice.resolveAddresses(bob.peerId(), 120)  // timeout max 2 min (120 s)

        // testing
        assertNotNull(peeraddrs) // peeraddrs are the public IP addresses
        assertTrue(peeraddrs.isNotEmpty())


        bob.shutdown()
        alice.shutdown()
    }
}