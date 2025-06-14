package io.github.remmerw.asen.core

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.OctetString
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.bigint.BigInt
import dev.whyoleg.cryptography.bigint.decodeToBigInt
import dev.whyoleg.cryptography.bigint.encodeToByteArray
import dev.whyoleg.cryptography.bigint.toBigInt
import io.github.remmerw.asen.Keys
import io.github.remmerw.asen.LIBP2P_CERTIFICATE_EXTENSION
import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.Peeraddr
import io.github.remmerw.asen.identifyPeerId
import io.github.remmerw.asen.parseAddress
import io.github.remmerw.asen.parsePeerId
import io.github.remmerw.asen.quic.Certificate
import io.github.remmerw.asen.quic.SignatureScheme
import io.github.remmerw.asen.quic.StreamState
import io.github.remmerw.asen.sign
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.minus
import kotlinx.datetime.plus
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.experimental.xor
import kotlin.io.encoding.ExperimentalEncodingApi

const val TLS_HANDSHAKE = "libp2p-tls-handshake:"

const val MULTISTREAM_PROTOCOL: String = "/multistream/1.0.0"
const val DHT_PROTOCOL: String = "/ipfs/kad/1.0.0"
const val IDENTITY_PROTOCOL: String = "/ipfs/id/1.0.0"
const val RELAY_PROTOCOL_HOP: String = "/libp2p/circuit/relay/0.2.0/hop"
const val RELAY_PROTOCOL_STOP: String = "/libp2p/circuit/relay/0.2.0/stop"


private val EXTENSION_PREFIX = intArrayOf(1, 3, 6, 1, 4, 1, 53594)
private val PREFIXED_EXTENSION_ID = getPrefixedExtensionID(intArrayOf(1, 1))
val BYTES_EMPTY: ByteArray = byteArrayOf()


internal fun newSignature(keys: Keys, peeraddrs: List<Peeraddr>): ByteArray {
    val checkIfValid: MutableSet<PeerId> = mutableSetOf()
    var toVerify = BYTES_EMPTY
    for (peeraddr in peeraddrs) {
        checkIfValid.add(peeraddr.peerId)
        val encoded = peeraddr.encoded()
        toVerify = concat(toVerify, encoded)
    }

    // only addresses of the same peerId
    require(checkIfValid.size <= 1) { "Invalid usage" }

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


private fun concat(vararg arrays: IntArray): IntArray {
    var length = 0
    for (array in arrays) {
        length += array.size
    }
    val result = IntArray(length)
    var pos = 0
    for (array in arrays) {
        array.copyInto(result, pos, 0, array.size)
        pos += array.size
    }
    return result
}

private fun getPrefixedExtensionID(suffix: IntArray): IntArray {
    return concat(EXTENSION_PREFIX, suffix)
}


internal fun prefixToString(): String {
    var s = ""
    for (i in PREFIXED_EXTENSION_ID.indices) {
        if (i > 0) {
            s = "$s."
        }
        s += PREFIXED_EXTENSION_ID[i].toString()
    }
    return s
}

internal fun createHash(bytes: ByteArray): ByteArray {
    try {
        val digest = SHA256()
        return digest.digest(bytes)
    } catch (throwable: Throwable) {
        throw IllegalStateException(throwable)
    }
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
        return BYTES_EMPTY
    }

    val size = readUnsignedVariant(bytes)
    val frame = bytes.readByteArray(size)

    if (frame.isEmpty()) {
        return BYTES_EMPTY
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


// The libp2p handshake uses TLS 1.3 (and higher). Endpoints MUST NOT negotiate lower TLS versions.
//
// During the handshake, peers authenticate each other’s identity as described in Peer
// Authentication. Endpoints MUST verify the peer's identity. Specifically,
// this means that servers MUST require client authentication during the TLS handshake,
// and MUST abort a connection attempt if the client fails to provide the requested
// authentication information.
//
// When negotiating the usage of this handshake dynamically, via a protocol agreement mechanism
// like multistream-select 1.0, it MUST be identified with the following protocol ID: /tls/1.0.0
//
// [-> done see Connection.remoteCertificate() and the usage]
//
// In order to be able to use arbitrary key types, peers don’t use their host key to sign the
// X.509 certificate they send during the handshake. Instead, the host key is encoded into the
// libp2p Public Key Extension, which is carried in a self-signed certificate.
// [-> done see createCertificate]
//
// The key used to generate and sign this certificate SHOULD NOT be related to the host's key.
// Endpoints MAY generate a new key and certificate for every connection attempt, or they MAY
// reuse the same key and certificate for multiple connections.
// [-> done see createCertificate, use the certification for multiple connections, but
// generates a new one each time the application is started]
//
// Endpoints MUST choose a key that will allow the peer to verify the certificate (i.e.
// choose a signature algorithm that the peer supports), and SHOULD use a key payloadType that (a)
// allows for efficient signature computation, and (b) reduces the combined size of the
// certificate and the signature. In particular, RSA SHOULD NOT be used unless no elliptic
// curve algorithms are supported.
// [-> elliptic curve is used, NAMED_CURVE = "secp256r1"]
//
// Endpoints MUST NOT send a certificate chain that contains more than one certificate.
// The certificate MUST have NotBefore and NotAfter fields set such that the certificate
// is valid at the time it is received by the peer. When receiving the certificate chain,
// an endpoint MUST check these conditions and abort the connection attempt if (a) the
// presented certificate is not yet valid, OR (b) if it is expired. Endpoints MUST abort
// the connection attempt if more than one certificate is received, or if the certificate’s
// self-signature is not valid.
//
// The certificate MUST contain the libp2p Public Key Extension. If this extension is
// missing, endpoints MUST abort the connection attempt. This extension MAY be marked
// critical. The certificate MAY contain other extensions. Implementations MUST ignore
// non-critical extensions with unknown OIDs. Endpoints MUST abort the connection attempt
// if the certificate contains critical extensions that the endpoint does not understand.
//
// Certificates MUST omit the deprecated subjectUniqueId and issuerUniqueId fields.
// Endpoints MAY abort the connection attempt if either is present.
// [Not done, because it is not required, but easy to do]
//
// Note for clients: Since clients complete the TLS handshake immediately after sending the
// certificate (and the TLS ClientFinished message), the handshake will appear as having
// succeeded before the server had the chance to verify the certificate. In this state,
// the client can already send application data. If certificate verification fails on
// the server side, the server will close the connection without processing any data that
// the client sent.
// [-> done see Connection.remoteCertificate() and the usage]
@OptIn(ExperimentalEncodingApi::class)
internal fun createCertificate(keys: Keys): Certificate {

    val now: Instant = Clock.System.now()
    val notBefore = now.minus(1, DateTimeUnit.YEAR, TimeZone.UTC)
    val notAfter = now.plus(99, DateTimeUnit.YEAR, TimeZone.UTC)

    val oid = ObjectIdentifier(LIBP2P_CERTIFICATE_EXTENSION)


    // getting ECDSA algorithm
    val ecdsa = CryptographyProvider.Default.get(ECDSA)
    // creating key generator with the specified curve
    val keyPairGenerator = ecdsa.keyPairGenerator(EC.Curve.P256)
    // generating ECDSA key pair
    //  types here and below are not required, and just needed to hint reader
    val keyPair: ECDSA.KeyPair = keyPairGenerator.generateKeyBlocking()


    // This signature provides cryptographic proof that the peer was in possession of the
    // private host key at the time the certificate was signed. Peers MUST verify the
    // signature, and abort the connection attempt if signature verification fails.
    //
    // The public host key and the signature are ANS.1-encoded into the SignedKey data
    // structure, which is carried in the libp2p Public Key Extension.
    // The libp2p Public Key Extension is a X.509 extension with the Object
    // Identier 1.3.6.1.4.1.53594.1.1, allocated by IANA to the libp2p project at Protocol Labs.
    // The publicKey field of SignedKey contains the public host key of the endpoint
    val keyBytes = identifyPeerId(keys.peerId)


    // The public host key allows the peer to calculate the peer ID of the peer it is
    // connecting to. Clients MUST verify that the peer ID derived from the certificate
    // matches the peer ID they intended to connect to, and MUST abort the connection if
    // there is a mismatch.
    //
    // The peer signs the concatenation of the string libp2p-tls-handshake: and the encoded
    // public key that is used to generate the certificate carrying the libp2p
    // Public Key Extension, using its private host key. The public key is encoded as a
    // SubjectPublicKeyInfo structure as described in RFC 5280, Section 4.1:

    // SubjectPublicKeyInfo ::= SEQUENCE {
    //  algorithm             AlgorithmIdentifier,
    //  subject_public_key    BIT STRING
    // }
    // AlgorithmIdentifier  ::= SEQUENCE {
    //  algorithm             OBJECT IDENTIFIER,
    //  parameters            ANY DEFINED BY algorithm OPTIONAL
    // }

    val signature = sign(
        keys,
        concat(
            TLS_HANDSHAKE.encodeToByteArray(),
            keyPair.publicKey.encodeToByteArrayBlocking(EC.PublicKey.Format.DER)
        )
    )

    val bigInteger = now.toEpochMilliseconds().toBigInt()

    // Prepare the information required for generating an X.509 certificate.
    val name = "SERIALNUMBER=$bigInteger"


    val seq = Asn1.Sequence {
        +OctetString(keyBytes)
        +OctetString(signature)
    }

    val cryptoPublicKey = CryptoPublicKey.decodeFromDer(
        keyPair.publicKey.encodeToByteArrayBlocking(EC.PublicKey.Format.DER)
    )
    val tbsCrt = TbsCertificate(
        serialNumber = bigInteger.encodeToByteArray(),
        signatureAlgorithm = X509SignatureAlgorithm.ES256,
        issuerName = listOf(
            RelativeDistinguishedName(
                AttributeTypeAndValue.CommonName(Asn1String.UTF8(name))
            )
        ),
        validFrom = Asn1Time(notBefore),
        validUntil = Asn1Time(notAfter),
        subjectName = listOf(
            RelativeDistinguishedName(
                AttributeTypeAndValue.CommonName(Asn1String.UTF8(name))
            )
        ),
        publicKey = cryptoPublicKey,
        extensions = listOf(
            X509CertificateExtension(
                oid,
                critical = false,
                Asn1OctetString(seq.derEncoded)
            )
        )
    )

    val generator = keyPair.privateKey.signatureGenerator(
        dev.whyoleg.cryptography.algorithms.SHA256,
        ECDSA.SignatureFormat.DER
    )

    val signed = generator.generateSignatureBlocking(tbsCrt.encodeToDer())

    val certificate = X509Certificate(
        tbsCrt, X509SignatureAlgorithm.ES256,
        CryptoSignature.decodeFromDerOrNull(signed)!!
    )

    return Certificate(
        certificate, keyPair.publicKey,
        keyPair.privateKey, SignatureScheme.ECDSA_SECP256R1_SHA256
    )
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