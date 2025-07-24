package io.github.remmerw.asen

import io.github.remmerw.asen.core.connect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail


class ConnectTest {

    @Test
    fun swarmPeer(): Unit = runBlocking(Dispatchers.IO) {
        assertFailsWith<Exception> { // can be Timeout or Connect Exception dependent of Network
            val peerId = decodePeerId("12D3KooWSzPeHsfxULJwFiLeq6Qsx6TruezAwjZ619qsLhqC7cUR")

            // "139.178.68.146"
            val address = byteArrayOf(139.toByte(), 178.toByte(), 68.toByte(), 146.toByte())
            val peeraddr = createPeeraddr(peerId, address, 4001.toUShort())
            assertEquals(4001.toUShort(), peeraddr.port)

            assertTrue(peeraddr.inet4())
            assertFalse(peeraddr.inet6())

            assertEquals(peeraddr.peerId, peerId)

            // peeraddr is just a fiction (will fail)
            val asen = newAsen()
            connect(asen, peeraddr)
            fail() // should not reached this point
        }
    }


    @Test
    fun testReservations(): Unit = runBlocking(Dispatchers.IO) {

        val server = newAsen()
        val addresses = server.observedAddresses()
        assertTrue(addresses.isNotEmpty())

        val publicAddresses = addresses.map { address ->
            InetSocketAddress(address, 5001)
        }
        server.makeReservations(publicAddresses, 25, 120)


        val peeraddrs = server.reservations()
        for (addr in peeraddrs) {
            println("Reservation Address $addr")
        }
        println("Number of reservations " + server.numReservations())

        if (!server.hasReservations()) {
            println("nothing to test no dialable addresses")
            return@runBlocking
        }

        for (address in server.reservations()) {
            println(address)
        }
        server.shutdown()
    }

}
