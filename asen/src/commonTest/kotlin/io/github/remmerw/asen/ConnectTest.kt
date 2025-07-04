package io.github.remmerw.asen

import io.github.remmerw.asen.core.connect
import io.github.remmerw.asen.core.identify
import io.github.remmerw.asen.quic.Connection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
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

            assertTrue(peeraddr.address.inet4())
            assertFalse(peeraddr.address.inet6())

            assertEquals(peeraddr.peerId, peerId)

            // peeraddr is just a fiction (will fail)
            val asen = newAsen()
            connect(asen, peeraddr)
            fail() // should not reached this point
        }
    }


    @Test
    fun testIdentify(): Unit = runBlocking(Dispatchers.IO) {

        val server = newAsen()
        val addresses = server.observedAddresses()
        assertTrue(addresses.isNotEmpty())

        val publicAddresses = listOf(
            Peeraddr(
                server.peerId(), addresses.first(), 5001.toUShort()
            )
        )
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

        for (peeraddr in server.reservations()) {


            var connection: Connection
            try {
                connection = connect(server, peeraddr)
            } catch (throwable: Throwable) {
                println(
                    "Connection failed peeraddr " + throwable.message
                )
                continue
            }

            try {
                assertNotNull(connection)
                val info = identify(connection)
                assertNotNull(info)
            } catch (throwable: Throwable) {
                error(throwable)
            }

            assertNotNull(connection)
            connection.close()
        }
        server.shutdown()
    }

}
