package io.github.remmerw.asen

import io.github.remmerw.asen.core.AddressUtil
import io.github.remmerw.asen.core.DhtPeer
import io.github.remmerw.asen.core.DhtPeers
import io.github.remmerw.asen.core.Key
import io.github.remmerw.asen.core.createDhtPeer
import io.github.remmerw.asen.core.createKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DhtPeersTest {
    @Test
    fun saturationModeNotReplaced(): Unit = runBlocking(Dispatchers.IO) {
        val dhtPeers = DhtPeers(100)
        assertNotNull(dhtPeers)

        val key = createKey("Moin".encodeToByteArray())
        val perfect = perfect(key)
        dhtPeers.add(random(key))
        dhtPeers.add(random(key))
        dhtPeers.add(perfect)

        // check order
        val first = dhtPeers.first()
        assertNotNull(first)
        val last = dhtPeers.last()
        assertNotNull(last)


        val res = first.distance.compareTo(last.distance)
        // if value is negative first is closer to key (which is the way)
        assertTrue(res < 0)

    }

    @Test
    fun saturationModeReplaced(): Unit = runBlocking(Dispatchers.IO) {
        val dhtPeers = DhtPeers(100)
        assertNotNull(dhtPeers)

        val key = createKey("Moin".encodeToByteArray())
        val a = random(key)
        dhtPeers.add(a)
        val b = random(key)
        dhtPeers.add(b)

        dhtPeers.add(perfect(key))


        // check order
        val first = dhtPeers.first()
        assertNotNull(first)
        val last = dhtPeers.last()
        assertNotNull(last)

        val res = first.distance.compareTo(last.distance)
        // if value is negative first is closer to key (which is the way)
        assertTrue(res < 0)
    }

    @Test
    fun random(): Unit = runBlocking(Dispatchers.IO) {
        val dhtPeers = DhtPeers(100)
        assertNotNull(dhtPeers)

        val key = createKey("Moin".encodeToByteArray())

        repeat(20) {
            val a = random(key)
            dhtPeers.add(a)
        }

        dhtPeers.add(perfect(key))

        var previous: DhtPeer? = null
        do {
            val nextPeer = dhtPeers.nextPeer()
            if (nextPeer != null) {
                if (previous != null) {
                    val res = previous.compareTo(nextPeer)
                    // if value is negative first is closer to key (which is the way)
                    assertTrue(res < 0)
                }
                previous = nextPeer
            }
        } while (nextPeer != null)
    }


    @Test
    fun fill(): Unit = runBlocking(Dispatchers.IO) {
        val dhtPeers = DhtPeers(100)
        assertNotNull(dhtPeers)

        val key = createKey("Moin".encodeToByteArray())
        repeat(20) {
            val a = random(key)
            dhtPeers.add(a)
        }

        // check order
        val first = dhtPeers.first()
        assertNotNull(first)
        val last = dhtPeers.last()
        assertNotNull(last)

        val res = first.distance.compareTo(last.distance)
        // if value is negative first is closer to key (which is the way)
        assertTrue(res < 0)
    }


    private fun random(key: Key): DhtPeer {
        val random = TestEnv.randomPeerId()
        val address = AddressUtil.textToNumericFormatV6("::1")!!
        val peeraddr = createPeeraddr(random, address, 4001.toUShort())

        return createDhtPeer(peeraddr, false, key)
    }

    private fun perfect(key: Key): DhtPeer {
        val random = PeerId(key.hash)

        val address = AddressUtil.textToNumericFormatV6("::1")!!
        val peeraddr = createPeeraddr(random, address, 4001.toUShort())
        return createDhtPeer(peeraddr, false, key)
    }
}
