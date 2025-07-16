package io.github.remmerw.asen

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Examples {

    @OptIn(ExperimentalAtomicApi::class)
    @Test
    fun resolveAddresses(): Unit = runBlocking(Dispatchers.IO) {

        val connectId = AtomicReference<PeerId?>(null)

        val bob = newAsen(holePunch = object : HolePunch {
            override fun invoke(
                peerId: PeerId,
                addresses: List<SocketAddress>
            ) {
                connectId.store(peerId)
                debug("Peer $peerId wants to connect with $addresses")
            }

        })
        val alice = newAsen()

        val addresses = bob.observedAddresses()
        assertTrue(addresses.isNotEmpty(), "Observer Addresses not defined")

        // Use Case : alice wants to connect to bob
        // [1] bob has to make reservations to relays
        val bobPublicAddresses = addresses.map { address ->
            SocketAddress(address.bytes, 5555.toUShort()) // 5555 bob server
        }

        // Note: bob has a service running on port 5001
        bob.makeReservations(
            bobPublicAddresses,
            20,
            120
        )  // timeout max 2 min (120 s) or 20 relays

        println("Reservations " + bob.numReservations())

        assertTrue(bob.hasReservations())

        // [2] alice can find bob addresses via its peerId


        val alicPublicAddresses = addresses.map { address ->
            SocketAddress(address.bytes, 7777.toUShort()) // 7777 alice server
        }

        val peeraddrs = alice.resolveAddresses(bob.peerId(), 120,
            alicPublicAddresses)  // timeout max 2 min (120 s)

        // testing
        assertNotNull(peeraddrs) // peeraddrs are the public IP addresses
        assertTrue(peeraddrs.isNotEmpty())

        // testing that alice actually wants to connect to bob

        assertEquals(connectId.load(), alice.peerId())

        bob.shutdown()
        alice.shutdown()
    }
}