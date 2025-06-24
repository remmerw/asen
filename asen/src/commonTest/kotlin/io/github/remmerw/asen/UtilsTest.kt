package io.github.remmerw.asen

import io.github.andreypfau.curve25519.ed25519.Ed25519
import io.github.remmerw.asen.core.AddressUtil
import io.github.remmerw.asen.core.BYTES_EMPTY
import io.github.remmerw.asen.core.HopMessage
import io.github.remmerw.asen.core.Status
import io.github.remmerw.asen.core.createPeerIdKey
import io.github.remmerw.asen.core.keyDistance
import io.github.remmerw.asen.core.readUnsignedVariant
import io.github.remmerw.asen.core.unsignedVariantSize
import io.github.remmerw.asen.core.writeUnsignedVariant
import kotlinx.coroutines.runBlocking
import kotlinx.io.Buffer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class UtilsTest {

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun testHopMessage() {

        val hopMessage = HopMessage(
            type = HopMessage.Type.STATUS,
            status = Status.OK
        )

        val data = ProtoBuf.encodeToByteArray<HopMessage>(hopMessage)

        val msg = ProtoBuf.decodeFromByteArray<HopMessage>(data)
        checkNotNull(msg)

        assertEquals(msg.type, HopMessage.Type.STATUS)
        assertEquals(msg.status, Status.OK)

    }

    @Test
    fun testBuilder(): Unit = runBlocking {
        val asen = newAsen()
        assertNotNull(asen)
        assertNotNull(asen.certificate())
        assertNotNull(asen.peerStore())
    }


    @Test
    fun stressToBase58() {
        repeat(TestEnv.ITERATIONS) {
            val peerId = TestEnv.randomPeerId()
            val toBase58 = encodePeerId(peerId)
            assertNotNull(toBase58)
            val cmp = decodePeerId(toBase58)
            assertEquals(peerId, cmp)
        }
    }


    @Test
    fun peerIdRandom() {
        val peerId = TestEnv.randomPeerId()
        val bytes = peerId.hash
        assertEquals(PeerId(bytes), peerId)
    }

    @Test
    fun emptyData() {
        val data = BYTES_EMPTY

        val size = unsignedVariantSize(data.size.toLong()) + data.size

        val buffer = Buffer()
        writeUnsignedVariant(buffer, data.size.toLong())
        buffer.write(data)
        assertEquals(buffer.size, size.toLong())


        val dataSize = readUnsignedVariant(buffer)
        assertEquals(dataSize, 0)
        assertTrue(buffer.exhausted())

    }


    @Test
    fun distance(): Unit = runBlocking {
        val peerId = TestEnv.randomPeerId()


        val a = createPeerIdKey(peerId)
        val b = createPeerIdKey(peerId)


        val dist = keyDistance(a, b)
        assertEquals(dist.toLong(), 0L)


        val random = TestEnv.randomPeerId()

        val r1 = createPeerIdKey(random)

        val distCmp = keyDistance(a, r1)
        assertNotEquals(distCmp.toLong(), 0L)
    }


    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun ed25519() {
        val keys = generateKeys()

        val peerId = keys.peerId

        val msg = "moin moin".encodeToByteArray()
        val signature = sign(keys, msg)


        val privateKeyAsString = Base64.encode(keys.privateKey)
        assertNotNull(privateKeyAsString)
        val publicKeyAsString = Base64.encode(keys.peerId.hash)
        assertNotNull(publicKeyAsString)


        val privateKey = Base64.decode(privateKeyAsString)
        assertNotNull(privateKey)

        val edPrivateKey = Ed25519.keyFromSeed(privateKey)
        assertNotNull(edPrivateKey)

        val publicKey = Base64.decode(publicKeyAsString)

        val peerIdCmp = PeerId(publicKey)

        assertEquals(peerId, peerIdCmp)

        assertTrue(edPrivateKey.publicKey().toByteArray().contentEquals(peerId.hash))

        verify(peerIdCmp, msg, signature)

        val storedKeys = generateKeys(privateKey)
        assertTrue(keys.privateKey.contentEquals(storedKeys.privateKey))
        assertEquals(keys.peerId, storedKeys.peerId)

    }


    @Test
    fun peerIdsDecoding() {
        val random = TestEnv.randomPeerId()

        // -- Peer ID (sha256) encoded as a raw base58btc multihash
        var peerId = decodePeerId("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
        assertNotNull(peerId)

        //  -- Peer ID (ed25519, using the "identity" multihash) encoded as a raw base58btc multihash
        peerId = decodePeerId("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA")
        assertNotNull(peerId)

        peerId = decodePeerId(encodePeerId(random))
        assertNotNull(peerId)
        assertEquals(peerId, random)
    }


    @Test
    fun ipv6Test() {
        val address = AddressUtil.textToNumericFormatV6("2804:d41:432f:3f00:ccbd:8e0d:a023:376b")
        assertNotNull(address)
        assertNotNull(
            createPeeraddr(
                "12D3KooWQ6SJ5A3uX5WjxCNbEbdAu8ufKJ3TmcjReTLSGaFk4HDU",
                address,
                4001.toUShort()
            )
        )
    }


    @Test
    fun peerStoreTest() {
        val port = 4001
        val random = TestEnv.randomPeerId()
        val address = byteArrayOf(127, 0, 0, 1)
        val publicAddresses = listOf(Peeraddr(random, address, port.toUShort()))

        publicAddresses.forEach { peeraddr ->
            assertNotNull(peeraddr)
            val data = peeraddr.encoded()
            assertNotNull(data)
            val cmp = parsePeeraddr(random, data)
            assertNotNull(cmp)
            assertEquals(peeraddr, cmp)
        }
    }

}
