package io.github.remmerw.asen.core

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.bigint.BigInt
import dev.whyoleg.cryptography.bigint.decodeToBigInt
import io.github.remmerw.asen.Address
import io.github.remmerw.asen.Asen
import io.github.remmerw.asen.MIXED_MODE
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.SocketAddress
import io.github.remmerw.asen.core.AddressUtil.textToNumericFormatV4
import io.github.remmerw.asen.core.AddressUtil.textToNumericFormatV6
import io.github.remmerw.asen.createPeeraddr
import io.github.remmerw.asen.debug
import io.github.remmerw.asen.parseAddress
import io.github.remmerw.asen.parsePeerId
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.asen.quic.StreamState
import io.github.remmerw.borr.Keys
import io.github.remmerw.borr.PeerId
import io.github.remmerw.borr.sign
import io.github.remmerw.frey.DnsResolver
import io.github.remmerw.frey.defaultDnsServer
import io.github.remmerw.frey.defaultDnsServerIpv6
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.experimental.xor
import kotlin.io.encoding.ExperimentalEncodingApi

const val MULTISTREAM_PROTOCOL: String = "/multistream/1.0.0"
const val DHT_PROTOCOL: String = "/ipfs/kad/1.0.0"
const val IDENTITY_PROTOCOL: String = "/ipfs/id/1.0.0"
const val RELAY_PROTOCOL_HOP: String = "/libp2p/circuit/relay/0.2.0/hop"
const val RELAY_PROTOCOL_STOP: String = "/libp2p/circuit/relay/0.2.0/stop"

internal fun newSignature(keys: Keys, addresses: List<SocketAddress>): ByteArray {
    var toVerify = byteArrayOf()
    for (address in addresses) {
        val encoded = address.encoded()
        toVerify = concat(toVerify, encoded)
    }

    return sign(keys, toVerify)
}


internal fun createPeeraddrs(peerId: PeerId, byteStrings: List<ByteArray>): List<Peeraddr> {
    val peeraddrs = mutableListOf<Peeraddr>()
    for (entry in byteStrings) {
        val peeraddr = parseAddress(peerId, entry)
        if (peeraddr != null) {
            peeraddrs.add(peeraddr)
        }
    }
    return peeraddrs
}


internal fun reachablePeeraddr(peerIdRaw: ByteArray, addresses: List<ByteArray>): Peeraddr? {
    val peerId = parsePeerId(peerIdRaw)
    if (peerId != null) {
        val peeraddrs = createPeeraddrs(peerId, addresses)
        for (peer in peeraddrs) {
            if (!peer.isLanAddress()) {
                return peer
            }
        }
    }
    return null
}

internal fun createHash(bytes: ByteArray): ByteArray {
    return CryptographyProvider.Default
        .get(SHA256)
        .hasher()
        .hashBlocking(bytes)
}

internal fun createKey(target: ByteArray): Key {
    return Key(createHash(target), target)
}

fun createPeerIdKey(peerId: PeerId): Key {
    return createKey(peerId.hash)
}

internal fun keyDistance(a: Key, b: Key): BigInt {
    // SetBytes interprets buf as the bytes of a big-endian unsigned
    // integer, sets z to that value, and returns z.
    // big.NewInt(0).SetBytes(k3)

    return keyDistance(a.hash, b.hash)
}


internal fun keyDistance(a: ByteArray, b: ByteArray): BigInt {
    val k3 = xor(a, b)

    // SetBytes interprets buf as the bytes of a big-endian unsigned
    // integer, sets z to that value, and returns z.
    // big.NewInt(0).SetBytes(k3)
    return k3.decodeToBigInt()
}

private fun xor(x1: ByteArray, x2: ByteArray): ByteArray {
    val out = ByteArray(x1.size)

    for (i in x1.indices) {
        out[i] = x1[i].xor(x2[i])
    }
    return out
}

internal fun receiveResponse(data: Buffer): ByteArray {
    return transform(data)
}

private fun transform(bytes: Buffer): ByteArray {
    if (bytes.size == 0L) {
        return byteArrayOf()
    }

    val size = readUnsignedVariant(bytes)
    val frame = bytes.readByteArray(size)

    if (frame.isEmpty()) {
        return byteArrayOf()
    } else {

        if (!StreamState.isProtocol(frame)) {
            return frame
        }

        return transform(bytes)
    }
}

internal fun readUnsignedVariant(buffer: Buffer): Int {
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

internal fun unsignedVariantSize(value: Long): Int {
    var remaining = value shr 7
    var count = 0
    while (remaining != 0L) {
        remaining = remaining shr 7
        count++
    }
    return count + 1
}


internal fun writeUnsignedVariant(buffer: Buffer, value: Long) {
    var x = value
    var remaining = x ushr 7
    while (remaining != 0L) {
        buffer.writeByte(((x and 0x7fL) or 0x80L).toByte())
        x = remaining
        remaining = remaining ushr 7
    }
    buffer.writeByte((x and 0x7fL).toByte())
}

private fun encode(data: ByteArray, buffer: Buffer) {
    writeUnsignedVariant(buffer, data.size.toLong())
    buffer.write(data)
}


private fun encodeProtocol(protocol: String, buffer: Buffer) {
    val data = protocol.encodeToByteArray()
    val length = data.size + 1 // 1 is "\n"
    writeUnsignedVariant(buffer, length.toLong())
    buffer.write(data)
    buffer.writeByte('\n'.code.toByte())
}


internal fun encode(vararg protocols: String): Buffer {
    val buffer = Buffer()
    for (i in protocols.indices) {
        val protocol = protocols[i]
        encodeProtocol(protocol, buffer)
    }
    return buffer
}


internal fun encode(message: ByteArray, vararg protocols: String): Buffer {
    val buffer = Buffer()
    for (i in protocols.indices) {
        val protocol = protocols[i]
        encodeProtocol(protocol, buffer)
    }
    encode(message, buffer)
    return buffer
}

@OptIn(ExperimentalEncodingApi::class)
internal fun createCertificate(keys: Keys): Certificate {
    return generateCertificate(keys)
}


internal fun concat(vararg chunks: ByteArray): ByteArray {
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

internal fun resolveAddresses(): Set<Peeraddr> {
    val addresses: MutableSet<Peeraddr> = mutableSetOf()

    val dnsServer = if (MIXED_MODE) {
        defaultDnsServer()
    } else {
        defaultDnsServerIpv6()
    }

    val dnsResolver = DnsResolver(dnsServer)
    resolveAddresses(
        dnsResolver,
        "bootstrap.libp2p.io", mutableSetOf()
    ).forEach { entry ->
        try {
            val tokens = entry.split('/')
            val ip = tokens[1]
            val host = tokens[2]
            val port = tokens[4].toUShort()
            val peerId = tokens[7]

            if (MIXED_MODE) {
                if (ip == "ip4") {
                    val peeraddr = createPeeraddr(
                        peerId,
                        textToNumericFormatV4(host)!!, port
                    )
                    addresses.add(peeraddr)
                } else if (ip == "ip6") {
                    val peeraddr = createPeeraddr(
                        peerId,
                        textToNumericFormatV6(host)!!, port
                    )
                    addresses.add(peeraddr)
                }
            } else {
                if (ip == "ip6") {
                    val peeraddr = createPeeraddr(
                        peerId,
                        textToNumericFormatV6(host)!!, port
                    )
                    addresses.add(peeraddr)
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        }
    }
    return addresses
}


@OptIn(ExperimentalAtomicApi::class)
suspend fun observedAddresses(asen: Asen): Set<Address> = coroutineScope {

    val result: MutableSet<Address> = ConcurrentHashMap.newKeySet()
    val addresses = resolveAddresses() // this you can trust

    addresses.forEach { peeraddr ->
        launch {
            val observed = observedAddress(asen, peeraddr)
            if (observed != null) {
                if (MIXED_MODE) {
                    result.add(observed)
                } else {
                    if (observed.inet6()) {
                        result.add(observed)
                    }
                }
            }
        }
    }

    result
}


@OptIn(ExperimentalCoroutinesApi::class)
internal fun CoroutineScope.makeReservation(
    asen: Asen,
    handledRelays: MutableSet<PeerId>,
    signatureMessage: SignatureMessage,
    channel: ReceiveChannel<Connection>
):
        ReceiveChannel<Connection> = produce {
    channel.consumeEach { connection ->
        // handled relays with given peerId
        if (handledRelays.add(connection.remotePeerId())) {

            // add stop handler to connection
            connection.responder().protocols.put(
                RELAY_PROTOCOL_STOP, RelayStopHandler(
                    asen.holePunch(), asen.peerId(), signatureMessage
                )
            )

            launch {
                if (makeReservation(asen, connection)) {
                    send(connection)
                }
            }
        }
    }
}

@OptIn(ExperimentalAtomicApi::class)
internal suspend fun doReservations(
    asen: Asen,
    addresses: List<SocketAddress>,
    maxReservation: Int,
    timeout: Int
) {

    val handledRelays: MutableSet<PeerId> = mutableSetOf()

    // check if reservations are still valid and not expired
    for (connection in asen.connector().connections()) {
        if (connection.isMarked()) {
            handledRelays.add(connection.remotePeerId()) // still valid
        }
    }
    val signature = newSignature(asen.keys(), addresses)
    val signatureMessage = relayMessage(signature, addresses)
    val valid = AtomicInt(handledRelays.size)


    val key = createPeerIdKey(asen.peerId())
    // fill up reservations [not yet enough]
    withTimeoutOrNull(timeout * 1000L) {

        try {
            val channel = closestPeers(asen, key)
            val result = makeReservation(asen, handledRelays, signatureMessage, channel)

            result.consumeEach { connection ->
                if (valid.incrementAndFetch() > maxReservation) {
                    // done
                    coroutineContext.cancelChildren()
                }
            }
        } catch (_: Throwable) {
        }
    }
}


private suspend fun makeReservation(asen: Asen, connection: Connection): Boolean {
    connection.enableKeepAlive()
    try {
        reserveHop(connection, asen.peerId())
        connection.mark()
        return true
    } catch (_: Throwable) {
        connection.close()
        return false
    }
}


private suspend fun observedAddress(asen: Asen, peeraddr: Peeraddr): Address? {
    var connection: Connection? = null
    try {
        connection = connect(asen, peeraddr)

        asen.peerStore().store(peeraddr)
        val info = identify(connection)
        if (info.observedAddress != null) {
            val observed = parseAddress(info.observedAddress)
            if (observed != null) {
                return observed.toAddress()
            }
        }

    } catch (throwable: Throwable) {
        debug("Error message " + throwable.message)
    } finally {
        connection?.close()
    }

    return null
}

private fun resolveAddresses(
    dnsResolver: DnsResolver,
    host: String,
    hosts: MutableSet<String>
): Set<String> {
    val result: MutableSet<String> = mutableSetOf()
    if (!hosts.add(host)) {
        return result
    }
    dnsResolver.resolveDnsAddr(host).forEach { entry ->
        if (entry.startsWith("/dnsaddr/")) {
            var child = entry.replaceFirst("/dnsaddr/", "")
            val index = child.indexOf('/')
            if (index > 0) {
                child = child.substring(0, index)
                result.addAll(resolveAddresses(dnsResolver, child, hosts))
            } else {
                result.addAll(resolveAddresses(dnsResolver, child, hosts))
            }
        } else {
            if (entry.contains("/quic-v1/p2p/")) {
                result.add(entry)
            }
        }

    }
    return result
}