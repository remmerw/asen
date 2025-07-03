package io.github.remmerw.asen

import io.github.andreypfau.curve25519.ed25519.Ed25519
import io.github.andreypfau.curve25519.ed25519.Ed25519PrivateKey
import io.github.andreypfau.curve25519.ed25519.Ed25519PublicKey
import io.github.remmerw.asen.core.Base58
import io.github.remmerw.asen.core.closestPeers
import io.github.remmerw.asen.core.connect
import io.github.remmerw.asen.core.connectHop
import io.github.remmerw.asen.core.createCertificate
import io.github.remmerw.asen.core.createPeerIdKey
import io.github.remmerw.asen.core.decodePeerIdByName
import io.github.remmerw.asen.core.doReservations
import io.github.remmerw.asen.core.hopRequest
import io.github.remmerw.asen.core.newSignature
import io.github.remmerw.asen.core.observedAddress
import io.github.remmerw.asen.core.prefixToString
import io.github.remmerw.asen.core.relayMessage
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.Connector
import io.ktor.network.selector.SelectorManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.io.readUShort
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random

internal const val MIXED_MODE = true
internal const val DHT_ALPHA: Int = 30
internal const val DHT_CONCURRENCY: Int = 5
internal const val TIMEOUT: Int = 5 // in seconds
val LIBP2P_CERTIFICATE_EXTENSION: String = prefixToString()


interface PeerStore {
    suspend fun peeraddrs(limit: Int): List<Peeraddr>

    suspend fun store(peeraddr: Peeraddr)
}

class Asen internal constructor(
    private val keys: Keys,
    private val certificate: Certificate,
    private val bootstrap: List<Peeraddr>,
    private val peerStore: PeerStore
) {
    private val selectorManager = SelectorManager(Dispatchers.IO)
    private val connector: Connector = Connector()
    private val mutex = Mutex()

    /**
     * This function tries to evaluate its own IP address
     * (public IPv6 addresses are in favour of IPv4)
     */
    suspend fun observedAddress(): ByteArray? {
        return observedAddress(this)
    }

    /**
     * Resolve the peer addresses with given target peer ID and a relay address.
     *
     * @param relay address of the relay which should be used to a relayed connection
     * @param target the target peer ID which addresses should be retrieved

     * @return list of the peer addresses (usually one IPv6 address)
     */
    suspend fun resolveAddresses(relay: Peeraddr, target: PeerId): List<Peeraddr> {
        var connection: Connection? = null
        val signature = newSignature(keys, emptyList())
        val signatureMessage = relayMessage(signature, emptyList())
        try {
            connection = connect(this, relay)
            return connectHop(connection, target, signatureMessage)
        } catch (throwable: Throwable){
            debug("Error message " + throwable.message)
        } finally {
            connection?.close()
        }
        return emptyList()
    }

    /**
     * Resolve the peer addresses of given target peer ID via the **libp2p** relay mechanism.
     *
     * @param target the target peer ID which addresses should be retrieved
     * @param timeout in seconds
     * @return list of the peer addresses (usually one IPv6 address)
     */
    @OptIn(ExperimentalAtomicApi::class)
    suspend fun resolveAddresses(target: PeerId, timeout: Long): List<Peeraddr> {
        val done = AtomicReference(emptyList<Peeraddr>())
        val signature = newSignature(keys, emptyList())
        val signatureMessage = relayMessage(signature, emptyList())
        val key = createPeerIdKey(target)

        withTimeoutOrNull(timeout * 1000L) {
            try {
                val channel = closestPeers(this@Asen, key)
                val result = hopRequest(target, signatureMessage, channel)
                result.consumeEach { addresses ->
                    done.store(addresses)
                    coroutineContext.cancelChildren()
                }
            } catch (_: Throwable) {
            }
        }
        return done.load()
    }

    /**
     * Makes a reservation to relay nodes with the purpose that other peers can find you via
     * the its peerId
     *
     * Note: when a reservation is just happening no further reservation is possible (mutex - protection)
     *
     * @param peeraddrs the peeraddrs which should be announced to connecting peers via relays
     * @param maxReservation number of max reservations
     * @param timeout in seconds
     */
    suspend fun makeReservations(
        peeraddrs: List<Peeraddr>,
        maxReservation: Int,
        timeout: Int
    ) {
        if (mutex.tryLock()) {
            try {
                doReservations(this, peeraddrs, maxReservation, timeout)
            } catch (throwable: Throwable) {
                debug(throwable)
            } finally {
                mutex.unlock()
            }
        }
    }

    /**
     * Returns all currently connected relays as a list of peer addresses
     *
     * @return list of relay peer addresses
     */
    fun reservations(): List<Peeraddr> {
        val peeraddrs = mutableListOf<Peeraddr>()
        for (connection in connector().connections()) {
            if (connection.isMarked()) {
                peeraddrs.add(connection.remotePeeraddr())
            }
        }
        return peeraddrs
    }

    fun hasReservations(): Boolean {
        return !reservations().isEmpty()
    }

    fun numReservations(): Int {
        return reservations().size
    }

    fun peerId(): PeerId {
        return keys.peerId
    }

    suspend fun shutdown() {
        try {
            selectorManager.close()
        } catch (throwable: Throwable) {
            debug(throwable)
        }
        try {
            connector.shutdown()
        } catch (throwable: Throwable) {
            debug(throwable)
        }
    }

    fun peerStore(): PeerStore {
        return peerStore
    }

    fun bootstrap(): List<Peeraddr> {
        return bootstrap
    }

    internal fun connector(): Connector {
        return connector
    }

    internal fun selectorManager(): SelectorManager {
        return selectorManager
    }

    internal fun certificate(): Certificate {
        return certificate
    }

    fun keys(): Keys {
        return keys
    }
}


/**
 * Create a new Asen instance
 *
 * @param keys public and private ed25519 keys for the peer ID, signing, verification and authentication
 * @param bootstrap initial bootstrap peers for the DHT (without bootstrap peers it can only be used for testing)
 * @param peerStore additional DHT peers (note the list will be filled and readout)
 */
fun newAsen(
    keys: Keys = generateKeys(),
    bootstrap: List<Peeraddr> = bootstrap(),
    peerStore: PeerStore = MemoryPeers()
): Asen {
    return Asen(keys, createCertificate(keys), bootstrap, peerStore)
}

class MemoryPeers : PeerStore {
    private val peers: MutableSet<Peeraddr> = mutableSetOf()
    private val mutex = Mutex()

    override suspend fun peeraddrs(limit: Int): List<Peeraddr> {
        mutex.withLock {
            return peers.take(limit).toList()
        }
    }

    override suspend fun store(peeraddr: Peeraddr) {
        mutex.withLock {
            peers.add(peeraddr)
        }
    }
}

fun bootstrap(): List<Peeraddr> {
    // "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
    val peeraddrs = mutableListOf<Peeraddr>()
    if(MIXED_MODE) {
        peeraddrs.add(
            createPeeraddr(
                "QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
                byteArrayOf(104.toByte(), 131.toByte(), 131.toByte(), 82.toByte()),
                4001.toUShort()
            )
        )
    }
    return peeraddrs
}


data class Peeraddr(val peerId: PeerId, val address: ByteArray, val port: UShort) :
    Comparable<Peeraddr> {
    init {
        require(address.size == 4 || address.size == 16) { "Invalid size for address" }
        require(port > 0.toUShort() && port <= 65535.toUShort()) {
            "Invalid port: $port"
        }
    }


    fun address(): String {
        return io.github.remmerw.asen.core.address(address)
    }

    fun encoded(): ByteArray {
        return io.github.remmerw.asen.core.encoded(address, port)
    }

    fun inet4(): Boolean {
        return address.size == 4
    }

    fun inet6(): Boolean {
        return address.size == 16
    }

    fun isLanAddress(): Boolean {
        return io.github.remmerw.asen.core.isLanAddress(address)
    }

    override fun hashCode(): Int {
        var result = peerId.hashCode()
        result = 31 * result + address.contentHashCode()
        result = 31 * result + port.hashCode()
        return result
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Peeraddr

        if (peerId != other.peerId) return false
        if (!address.contentEquals(other.address)) return false
        if (port != other.port) return false

        return true
    }

    override fun compareTo(other: Peeraddr): Int {
        val cmp = address.size.compareTo(other.address.size)
        return if (cmp != 0) {
            -cmp // ipv6 is higher priority
        } else {
            hashCode().compareTo(other.hashCode()) // good enough not perfect
        }
    }
}

// hash is always (32 bit) and it is a Ed25519 public key
data class PeerId(val hash: ByteArray) {

    override fun hashCode(): Int {
        return hash.contentHashCode() // ok, checked, maybe opt
    }

    init {
        require(hash.size == 32) { "hash size must be 32" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PeerId

        return hash.contentEquals(other.hash)
    }


    fun verify(data: ByteArray, signature: ByteArray) { // move to Asen
        require(
            Ed25519PublicKey(hash)
                .verify(data, signature)
        ) {
            "Data is not valid with signature"
        }
    }
}

// Note a peerId is always a public key (ed25519)
@Suppress("ArrayInDataClass")
data class Keys(val peerId: PeerId, val privateKey: ByteArray)


fun generateKeys(): Keys {

    val privateKey: Ed25519PrivateKey = Ed25519.generateKey(Random)
    val publicKey: Ed25519PublicKey = privateKey.publicKey()

    return Keys(
        PeerId(publicKey.toByteArray()),
        privateKey.seed()
    )
}

fun generateKeys(privateKey: ByteArray): Keys {

    val edPrivateKey = Ed25519.keyFromSeed(privateKey)
    val publicKey = edPrivateKey.publicKey()

    return Keys(
        PeerId(publicKey.toByteArray()),
        privateKey
    )
}

fun verify(peerId: PeerId, data: ByteArray, signature: ByteArray) { // move to Asen
    peerId.verify(data, signature)
}

fun sign(keys: Keys, data: ByteArray): ByteArray { // move to Asen
    return Ed25519.keyFromSeed(keys.privateKey).sign(data)
}


fun decode58(input: String): ByteArray {
    return Base58.decode58(input)
}

fun encode58(data: ByteArray): String {
    return Base58.encode58(data)
}

fun identifyPeerId(peerId: PeerId): ByteArray {
    return concat(Ed25519_PREFIX, peerId.hash)
}

fun identifyRaw(raw: ByteArray): PeerId {
    if (prefixArraysEquals(Ed25519_PREFIX, raw)) {
        return PeerId(raw.copyOfRange(Ed25519_PREFIX.size, raw.size))
    }
    throw IllegalStateException("Only Ed25519 expected")
}

fun parsePeerId(raw: ByteArray): PeerId? {
    try {
        if (prefixArraysEquals(Ed25519_ID_PREFIX, raw)) {
            val peerId = PeerId(
                raw.copyOfRange(Ed25519_ID_PREFIX.size, raw.size)
            )
            return peerId
        }
    } catch (_: Throwable) {
    }
    return null
}

fun createPeeraddr(peerId: PeerId, address: ByteArray, port: UShort): Peeraddr {
    return Peeraddr(peerId, address, port)
}

fun createPeeraddr(peerId: String, address: ByteArray, port: UShort): Peeraddr {
    return createPeeraddr(decodePeerId(peerId), address, port)
}


fun decodePeerId(name: String): PeerId { // special libp2p decoding
    return decodePeerIdByName(name)
}

fun encodePeerId(peerId: PeerId): String {  // special libp2p encoding
    return encode58(multihash(peerId))
}

fun parseAddress(peerId: PeerId, bytes: ByteArray): Peeraddr? {

    val cis = Buffer()
    cis.write(bytes)

    var address: ByteArray? = null
    var port = 0.toUShort()
    try {

        while (!cis.exhausted()) {
            val code = readUnsignedVariant(cis)

            if (size(code) == 0) {
                continue
            }

            val part = readPart(code, cis) ?: return null
            if (part is ByteArray) {
                address = part
            }
            if (part is UShort) {
                port = part
            }
        }
    } catch (_: Throwable) { // should not occur
        return null
    }

    // check if address has a port, when it is not a dnsAddr
    if (port > 0.toUShort() && address != null) {
        return Peeraddr(peerId, address, port)
    }
    return null
}

fun parsePeeraddr(peerId: PeerId, raw: ByteArray): Peeraddr {
    return checkNotNull(parseAddress(peerId, raw)) { "Not supported peeraddr" }
}

fun multihash(peerId: PeerId): ByteArray {
    return concat(Ed25519_ID_PREFIX, peerId.hash)
}


internal const val IP4: Int = 4
internal const val IP6: Int = 41
internal const val UDP: Int = 273
private const val QUIC_V1: Int = 461


private val Ed25519_ID_PREFIX = byteArrayOf(0, 36, 8, 1, 18, 32)
private val Ed25519_PREFIX = byteArrayOf(8, 1, 18, 32)


private fun size(code: Int): Int {
    return when (code) {
        IP4 -> 32
        IP6 -> 128
        UDP -> 16
        QUIC_V1 -> 0
        else -> -1
    }
}


private fun readUnsignedVariant(buffer: Buffer): Int {
    var result = 0
    var cur: Int
    var count = 0
    do {
        cur = buffer.readByte().toInt() and 0xff
        result = result or ((cur and 0x7f) shl (count * 7))
        count++
    } while (((cur and 0x80) == 0x80) && count < 5)
    check((cur and 0x80) != 0x80) { "invalid unsigned variant sequence" }
    return result
}

private fun sizeForAddress(code: Int, cis: Buffer): Int {
    val size = size(code)
    if (size > 0) return size / 8
    if (size == 0) return 0
    return readUnsignedVariant(cis)
}

private fun readPart(code: Int, cis: Buffer): Any? {
    try {
        val sizeForAddress = sizeForAddress(code, cis)
        when (code) {
            IP4, IP6 -> {
                val address = cis.readByteArray(sizeForAddress)
                return if (MIXED_MODE) {
                    address
                } else {
                    if (address.size == 4) { // only ipv4
                        address
                    } else {
                        null
                    }
                }
            }

            UDP -> {
                //val a = cis.readByte().toInt() and 0xFF
                //val b = cis.readByte().toInt() and 0xFF
                return cis.readUShort()
            }
        }
    } catch (_: Throwable) {
    }
    return null
}

private fun prefixArraysEquals(prefix: ByteArray, raw: ByteArray): Boolean {
    require(prefix.size < raw.size) { "Prefix not smaller" }
    for (i in prefix.indices) {
        if (prefix[i] != raw[i]) {
            return false
        }
    }
    return true
}


private fun concat(vararg chunks: ByteArray): ByteArray {
    var length = 0
    for (chunk in chunks) {
        check(length <= Int.MAX_VALUE - chunk.size) { "exceeded size limit" }
        length += chunk.size
    }
    val result = ByteArray(length)
    var pos = 0
    for (chunk in chunks) {
        chunk.copyInto(result, pos, 0, chunk.size)
        pos += chunk.size
    }
    return result
}


internal fun debug(message: String) {
    if (DEBUG) {
        println(message)
    }
}

internal fun debug(throwable: Throwable) {
    if (ERROR) {
        throwable.printStackTrace()
    }
}

private const val DEBUG: Boolean = false
private const val ERROR: Boolean = true