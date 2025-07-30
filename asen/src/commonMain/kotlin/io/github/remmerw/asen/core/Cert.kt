package io.github.remmerw.asen.core

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.bigint.toBigInt
import io.github.remmerw.asen.cert.ASN1Encodable
import io.github.remmerw.asen.cert.ASN1Object
import io.github.remmerw.asen.cert.ASN1ObjectIdentifier
import io.github.remmerw.asen.cert.ASN1OctetString
import io.github.remmerw.asen.cert.ASN1Primitive
import io.github.remmerw.asen.cert.DEROctetString
import io.github.remmerw.asen.cert.DERSequence
import io.github.remmerw.asen.cert.SubjectPublicKeyInfo
import io.github.remmerw.asen.cert.X500Name
import io.github.remmerw.asen.cert.X509v3CertificateBuilder
import io.github.remmerw.asen.identifyPeerId
import io.github.remmerw.asen.quic.SignatureScheme
import io.github.remmerw.borr.Keys
import io.github.remmerw.borr.sign
import java.time.ZoneId
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlin.time.toJavaInstant


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
// In order to be able to use arbitrary key types, peers don’t use their host key to sign the
// X.509 certificate they send during the handshake. Instead, the host key is encoded into the
// libp2p Public Key Extension, which is carried in a self-signed certificate.
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
@OptIn(ExperimentalEncodingApi::class, ExperimentalTime::class)
internal fun generateCertificate(keys: Keys): io.github.remmerw.asen.quic.Certificate {


    val now: Instant = Clock.System.now()
    now.plus(365.days).toJavaInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()

    val notBefore = now.minus(1.days).toJavaInstant()
        .atZone(ZoneId.systemDefault()).toLocalDateTime()
    val notAfter = now.plus(365.days).toJavaInstant()
        .atZone(ZoneId.systemDefault()).toLocalDateTime()


    val provider = CryptographyProvider.Default
    // getting ECDSA algorithm
    val ecdsa = provider.get(ECDSA)

    // creating key generator with the specified curve
    val keyPairGenerator = ecdsa.keyPairGenerator(EC.Curve.P256)

    // generating ECDSA key pair
    //  types here and below are not required, and just needed to hint reader
    val keyPair: ECDSA.KeyPair = keyPairGenerator.generateKeyBlocking()
    val key = keyPair.privateKey
    val pubKey = keyPair.publicKey

    val bigInteger = now.toEpochMilliseconds().toBigInt()

    // Prepare the information required for generating an X.509 certificate.
    val owner = X500Name("SERIALNUMBER=$bigInteger")


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
    val subjectPublicKeyInfo = SubjectPublicKeyInfo.Companion.getInstance(
        pubKey.encodeToByteArrayBlocking(EC.PublicKey.Format.DER)
    )


    val builder = X509v3CertificateBuilder(
        owner, bigInteger, notBefore, notAfter, owner, subjectPublicKeyInfo
    )

    val signature = sign(
        keys,
        concat(
            TLS_HANDSHAKE.encodeToByteArray(), subjectPublicKeyInfo.encoded()
        )
    )


    // This signature provides cryptographic proof that the peer was in possession of the
    // private host key at the time the certificate was signed. Peers MUST verify the
    // signature, and abort the connection attempt if signature verification fails.
    //
    // The public host key and the signature are ANS.1-encoded into the SignedKey data
    // structure, which is carried in the libp2p Public Key Extension.
    // The libp2p Public Key Extension is a X.509 extension with the Object
    // Identier 1.3.6.1.4.1.53594.1.1, allocated by IANA to the libp2p project at Protocol Labs.
    val signedKey = SignedKey(keyBytes, signature)

    val indent = ASN1ObjectIdentifier(LIBP2P_CERTIFICATE_EXTENSION)


    // The certificate MUST contain the libp2p Public Key Extension. If this extension is
    // missing, endpoints MUST abort the connection attempt. This extension MAY be
    // marked critical. The certificate MAY contain other extensions. Implementations
    // MUST ignore non-critical extensions with unknown OIDs. Endpoints MUST abort the
    // connection attempt if the certificate contains critical extensions that the
    // endpoint does not understand.

    val cert = builder.addExtension(indent, false, signedKey)
        .build("SHA256withECDSA", key)

    return io.github.remmerw.asen.quic.Certificate(
        cert, pubKey, key,
        SignatureScheme.ECDSA_SECP256R1_SHA256
    )
}

class SignedKey internal constructor(pubKey: ByteArray, signature: ByteArray) : ASN1Object() {
    private val pubKey: ASN1OctetString = DEROctetString(pubKey)
    private val signature: ASN1OctetString = DEROctetString(signature)

    override fun toASN1Primitive(): ASN1Primitive {
        val ansiEncodable = arrayOf<ASN1Encodable>(this.pubKey, this.signature)
        return DERSequence(ansiEncodable)
    }
}


private const val TLS_HANDSHAKE = "libp2p-tls-handshake:"
private val EXTENSION_PREFIX = intArrayOf(1, 3, 6, 1, 4, 1, 53594)
private val PREFIXED_EXTENSION_ID = getPrefixedExtensionID(intArrayOf(1, 1))

private val LIBP2P_CERTIFICATE_EXTENSION: String = prefixToString()

private fun getPrefixedExtensionID(suffix: IntArray): IntArray {
    return concat(EXTENSION_PREFIX, suffix)
}


private fun prefixToString(): String {
    var s = ""
    for (i in PREFIXED_EXTENSION_ID.indices) {
        if (i > 0) {
            s = "$s."
        }
        s += PREFIXED_EXTENSION_ID[i].toString()
    }
    return s
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