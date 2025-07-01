package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Examples {

    @Test
    fun testConnection(): Unit = runBlocking(Dispatchers.IO) {

        val bob = newAsen()
        val alice = newAsen()

        // Use Case : alice wants to connect to bob
        // [1] bob has to make reservations to relays
        val publicAddresses = listOf(

            // artificial address where the "data" server of bob is running
            Peeraddr(
                bob.peerId(),
                bob.publicAddress()!!,
                5001.toUShort()
            )
        )

        // Note: bob has a service running on port 5001
        bob.makeReservations(
            publicAddresses,
            20,
            120
        )  // timeout max 2 min (120 s) or 20 relays

        assertTrue(bob.hasReservations())

        // [2] alice can find bob via its peerId
        val peeraddrs = alice.findPeer(bob.peerId(), 120)  // timeout max 2 min (120 s)


        // testing
        assertNotNull(peeraddrs) // peeraddrs are the public IP addresses
        assertTrue(peeraddrs.isNotEmpty())

        val address = peeraddrs.first()
        assertEquals(address.peerId, bob.peerId())

        bob.shutdown()
        alice.shutdown()
    }
}