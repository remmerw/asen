package io.github.remmerw.asen


import io.github.remmerw.asen.core.Base58
import io.github.remmerw.asen.core.closestPeers
import io.github.remmerw.asen.core.createCertificate
import io.github.remmerw.asen.core.createPeerIdKey
import io.github.remmerw.asen.core.decodePeerIdByName
import io.github.remmerw.asen.core.doReservations
import io.github.remmerw.asen.core.hopRequest
import io.github.remmerw.asen.core.hostname
import io.github.remmerw.asen.core.newSignature
import io.github.remmerw.asen.core.observedAddresses
import io.github.remmerw.asen.core.prefixToString
import io.github.remmerw.asen.core.relayMessage
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.Connector
import io.github.remmerw.borr.Ed25519Sign
import io.github.remmerw.borr.Ed25519Verify
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.Dispatchers
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

internal const val MIXED_MODE = true
internal const val DHT_ALPHA: Int = 30
internal const val DHT_CONCURRENCY: Int = 5
internal const val TIMEOUT: Int = 5 // in seconds
val LIBP2P_CERTIFICATE_EXTENSION: String = prefixToString()

fun createInetSocketAddress(address: ByteArray, port: Int): InetSocketAddress {
    return InetSocketAddress(hostname(address), port)
}


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
     * This function tries to evaluate its own IP addresses by asking other peers (ipv4 and ipv6)
     */
    suspend fun observedAddresses(): Set<Address> {
        return observedAddresses(this)
    }

    /**
     * Resolve the addresses of given target peer ID via the **libp2p** relay mechanism.
     *
     * @param target the target peer ID which addresses should be resolved
     * @param timeout in seconds
     * @return list of the addresses (usually one IPv6 address)
     */
    @OptIn(ExperimentalAtomicApi::class)
    suspend fun resolveAddresses(target: PeerId, timeout: Long): List<SocketAddress> {
        val done = AtomicReference(emptyList<SocketAddress>())
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
     * @param addresses the addresses which should be announced via the relays
     * @param maxReservation number of max reservations
     * @param timeout in seconds
     */
    suspend fun makeReservations(
        addresses: List<SocketAddress>,
        maxReservation: Int,
        timeout: Int
    ) {
        if (mutex.tryLock()) {
            try {
                doReservations(this, addresses, maxReservation, timeout)
            } catch (throwable: Throwable) {
                debug(throwable)
            } finally {
                mutex.unlock()
            }
        }
    }

    /**
     * Returns all currently connected relays as a list of addresses
     *
     * @return list of relay addresses
     */
    fun reservations(): List<InetSocketAddress> {
        val peeraddrs = mutableListOf<InetSocketAddress>()
        for (connection in connector().connections()) {
            if (connection.isMarked()) {
                peeraddrs.add(connection.remoteAddress())
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
            connector.shutdown()
        } catch (throwable: Throwable) {
            debug(throwable)
        }

        try {
            selectorManager.close()
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
    if (MIXED_MODE) {
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

data class Address(val bytes: ByteArray) {
    init {
        if (MIXED_MODE) {
            require(bytes.size == 4 || bytes.size == 16) { "Invalid size for address" }
        } else {
            require(bytes.size == 16) { "Only ipv6 addresses are excepted" }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Address

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    fun inet4(): Boolean {
        return bytes.size == 4
    }

    fun inet6(): Boolean {
        return bytes.size == 16
    }
}

data class SocketAddress(val address: ByteArray, val port: UShort) {
    init {
        require(port > 0.toUShort() && port <= 65535.toUShort()) {
            "Invalid port: $port"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SocketAddress

        if (!address.contentEquals(other.address)) return false
        if (port != other.port) return false

        return true
    }

    override fun hashCode(): Int {
        var result = address.contentHashCode()
        result = 31 * result + port.hashCode()
        return result
    }

    fun toAddress(): Address {
        return Address(address)
    }

    fun encoded(): ByteArray {
        return io.github.remmerw.asen.core.encoded(address, port)
    }
}

data class Peeraddr(val peerId: PeerId, val address: ByteArray, val port: UShort) {
    init {
        require(port > 0.toUShort() && port <= 65535.toUShort()) {
            "Invalid port: $port"
        }
    }

    fun hostname(): String {
        return hostname(address)
    }

    fun toSocketAddress(): SocketAddress {
        return SocketAddress(address, port)
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Peeraddr

        if (peerId != other.peerId) return false
        if (!address.contentEquals(other.address)) return false
        if (port != other.port) return false

        return true
    }

    override fun hashCode(): Int {
        var result = peerId.hashCode()
        result = 31 * result + address.contentHashCode()
        result = 31 * result + port.hashCode()
        return result
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
}

// Note a peerId is always a public key (ed25519)
@Suppress("ArrayInDataClass")
data class Keys(val peerId: PeerId, val privateKey: ByteArray)


fun generateKeys(): Keys {
    val keyPair = Ed25519Sign.KeyPair.newKeyPair()
    return Keys(
        PeerId(keyPair.getPublicKey()),
        keyPair.getPrivateKey()
    )
}

fun verify(peerId: PeerId, data: ByteArray, signature: ByteArray) { // move to Asen
    val verifier = Ed25519Verify(peerId.hash)
    verifier.verify(signature, data)
}

fun sign(keys: Keys, data: ByteArray): ByteArray { // move to Asen
    val signer = Ed25519Sign(keys.privateKey)
    return signer.sign(data)
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

fun parseAddress(bytes: ByteArray): SocketAddress? {

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
        return SocketAddress(address, port)
    }
    return null
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
        return createPeeraddr(peerId, address, port)
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
            IP4 -> {
                val address = cis.readByteArray(sizeForAddress)
                return if (MIXED_MODE) {
                    address // ipv4 in mixed mode accepted
                } else {
                    null
                }
            }

            IP6 -> {
                return cis.readByteArray(sizeForAddress)
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