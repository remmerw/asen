package io.github.remmerw.asen


import io.github.remmerw.asen.core.closestPeers
import io.github.remmerw.asen.core.createCertificate
import io.github.remmerw.asen.core.createPeerIdKey
import io.github.remmerw.asen.core.decodePeerIdByName
import io.github.remmerw.asen.core.doReservations
import io.github.remmerw.asen.core.encoded
import io.github.remmerw.asen.core.hopRequest
import io.github.remmerw.asen.core.newSignature
import io.github.remmerw.asen.core.observedAddresses
import io.github.remmerw.asen.core.relayMessage
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.Connector
import io.github.remmerw.borr.Keys
import io.github.remmerw.borr.PeerId
import io.github.remmerw.borr.encode58
import io.github.remmerw.borr.generateKeys
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.io.readUShort
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

internal const val MIXED_MODE = true
internal const val DHT_ALPHA: Int = 30
internal const val DHT_CONCURRENCY: Int = 5
internal const val TIMEOUT: Int = 5 // in seconds


interface PeerStore {
    suspend fun peeraddrs(limit: Int): List<Peeraddr>

    suspend fun store(peeraddr: Peeraddr)
}

class DisabledHolePunch : HolePunch {
    override fun invoke(
        peerId: PeerId,
        addresses: List<InetSocketAddress>
    ) {
        debug("Peer $peerId wants to connect with $addresses")
    }
}

interface HolePunch {
    fun invoke(peerId: PeerId, addresses: List<InetSocketAddress>)
}

class Asen internal constructor(
    private val keys: Keys,
    private val certificate: Certificate,
    private val bootstrap: List<Peeraddr>,
    private val peerStore: PeerStore,
    private val holePunch: HolePunch
) {
    private val connector: Connector = Connector()
    private val mutex = Mutex()

    /**
     * This function tries to evaluate its own IP addresses by asking other peers (ipv4 and ipv6)
     */
    suspend fun observedAddresses(): Set<InetAddress> {
        return observedAddresses(this)
    }

    /**
     * Resolve the addresses of given target peer ID via the **libp2p** relay mechanism.
     *
     * @param target the target peer ID which addresses should be resolved
     * @param timeout in seconds
     * @param publicAddresses Own public addresses used for hole punching [Note: default empty
     * hole punching is deactivated]
     * @return list of the addresses (usually one IPv6 address)
     */
    @OptIn(ExperimentalAtomicApi::class)
    suspend fun resolveAddresses(
        target: PeerId, timeout: Long,
        publicAddresses: List<InetSocketAddress> = emptyList()
    ): List<InetSocketAddress> {
        val done = AtomicReference(emptyList<InetSocketAddress>())
        val signature = newSignature(keys, publicAddresses)
        val signatureMessage = relayMessage(signature, publicAddresses)
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
        addresses: List<InetSocketAddress>,
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
    fun reservations(): List<String> {
        val peeraddrs = mutableListOf<String>()
        for (connection in connector().connections()) {
            if (connection.isMarked()) {
                peeraddrs.add(connection.remoteAddress().toString())
            }
        }
        return peeraddrs
    }

    fun numReservations(): Int {
        return reservations().size
    }

    fun peerId(): PeerId {
        return keys.peerId
    }

    fun shutdown() {
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

    fun holePunch(): HolePunch {
        return holePunch
    }

    internal fun connector(): Connector {
        return connector
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
 * @param peerStore additional DHT peers (note it will be filled and readout during DHT operations)
 * @param holePunch Notification for doing hole punching
 */
fun newAsen(
    keys: Keys = generateKeys(),
    bootstrap: List<Peeraddr> = bootstrap(),
    peerStore: PeerStore = MemoryPeers(),
    holePunch: HolePunch = DisabledHolePunch()
): Asen {
    return Asen(keys, createCertificate(keys), bootstrap, peerStore, holePunch)
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


data class Peeraddr(val peerId: PeerId, val address: ByteArray, val port: UShort) {
    init {
        require(port > 0.toUShort() && port <= 65535.toUShort()) {
            "Invalid port: $port"
        }
    }


    fun inet4(): Boolean {
        return address.size == 4
    }

    fun inet6(): Boolean {
        return address.size == 16
    }

    fun toInetSocketAddress(): InetSocketAddress {
        return InetSocketAddress(
            InetAddress.getByAddress(address),
            port.toInt()
        )
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

    fun encoded(): ByteArray {
        return encoded(address, port)
    }

}

fun InetSocketAddress.encoded(): ByteArray {
    return encoded(address.address, port.toUShort())
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

fun parseAddress(bytes: ByteArray): InetSocketAddress? {

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
        val inetAddress = InetAddress.getByAddress(address)
        return InetSocketAddress(inetAddress, port.toInt())
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