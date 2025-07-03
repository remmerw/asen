package io.github.remmerw.asen.cert

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray


const val DER: String = "DER"
const val DECLARED_EXPLICIT = 1
const val DECLARED_IMPLICIT = 2
const val LONG_LIMIT = (Long.MAX_VALUE shr 7) - 0x7F

val ZERO_BYTES = ByteArray(0)
val EMPTY_OCTETS: ByteArray = ByteArray(0)


fun isValidIdentifier(identifier: String, from: Int): Boolean {
    var digitCount = 0

    var pos = identifier.length
    while (--pos >= from) {
        val ch = identifier[pos]

        when (ch) {
            '.' -> {
                if (0 == digitCount
                    || (digitCount > 1 && identifier[pos + 1] == '0')
                ) {
                    return false
                }

                digitCount = 0
            }

            in '0'..'9' -> {
                ++digitCount
            }

            else -> {
                return false
            }
        }
    }

    return 0 != digitCount
            && (digitCount <= 1 || identifier[pos + 1] != '0')
}

fun writeField(out: Buffer, value: Long) {
    var fieldValue = value
    val result = ByteArray(9)
    var pos = 8
    result[pos] = (fieldValue.toInt() and 0x7F).toByte()
    while (fieldValue >= (1L shl 7)) {
        fieldValue = fieldValue shr 7
        result[--pos] = (fieldValue.toInt() or 0x80).toByte()
    }
    out.write(result, pos, 9)
}

fun writeField(out: Buffer, fieldValue: BigInteger) {
    val byteCount = (fieldValue.bitLength() + 6) / 7
    if (byteCount == 0) {
        out.writeByte(0)
    } else {
        var tmpValue = fieldValue
        val tmp = ByteArray(byteCount)
        for (i in byteCount - 1 downTo 0) {
            tmp[i] = (tmpValue.intValue() or 0x80).toByte()
            tmpValue = tmpValue.shr(7)
        }
        tmp[byteCount - 1] = (tmp[byteCount - 1].toInt() and 0x7F).toByte()
        out.write(tmp, 0, tmp.size)
    }
}

fun getLengthOfDL(value: Int): Int {
    var dl = value
    if (dl < 128) {
        return 1
    }

    var length = 2
    while ((8.let { dl = dl ushr it; dl }) != 0) {
        ++length
    }
    return length
}

fun getLengthOfEncodingDL(withID: Boolean, contentsLength: Int): Int {
    return (if (withID) 1 else 0) + getLengthOfDL(contentsLength) + contentsLength
}

fun getLengthOfIdentifier(value: Int): Int {
    var tag = value
    if (tag < 31) {
        return 1
    }

    var length = 2
    while ((7.let { tag = tag ushr it; tag }) != 0) {
        ++length
    }
    return length
}

fun encodedLength(withTag: Boolean, contentsLength: Int): Int {
    return getLengthOfEncodingDL(withTag, contentsLength)
}

fun encode(out: ASN1OutputStream, withTag: Boolean, buf: ByteArray, len: Int) {
    out.writeEncodingDL(withTag, BERTags.BIT_STRING, buf, 0, len)
}

fun createOutputStream(out: Sink, encoding: String): ASN1OutputStream {
    return if (encoding == DER) {
        DEROutputStream(out)
    } else {
        ASN1OutputStream(out)
    }
}

/**
 * Convert a vector of bit strings into a single bit string
 */
fun flattenBitStrings(bitStrings: Array<ASN1BitString>): ByteArray {
    when (val count = bitStrings.size) {
        0 -> {
            // No bits
            return byteArrayOf(0)
        }

        1 -> {
            return bitStrings[0].contents
        }

        else -> {
            val last = count - 1
            var totalLength = 0
            var i = 0
            while (i < last) {
                val elementContents = bitStrings[i].contents
                require(elementContents[0].toInt() == 0) { "only the last nested bitstring can have padding" }

                totalLength += elementContents.size - 1
                ++i
            }

            // Last one can have padding
            val lastElementContents = bitStrings[last].contents
            val padBits = lastElementContents[0]
            totalLength += lastElementContents.size

            val contents = ByteArray(totalLength)
            contents[0] = padBits

            var pos = 1
            for (bitString in bitStrings) {
                val elementContents = bitString.contents
                val length = elementContents.size - 1
                elementContents.copyInto(contents, pos, 1, length)
                pos += length
            }

            //            assert pos == totalLength;
            return contents
        }
    }
}

/**
 * Convert a vector of octet strings into a single byte string
 */
fun flattenOctetStrings(octetStrings: Array<ASN1OctetString>): ByteArray {
    when (val count = octetStrings.size) {
        0 -> {
            return EMPTY_OCTETS
        }

        1 -> {
            return octetStrings[0].octets
        }

        else -> {
            var totalOctets = 0
            for (octetString in octetStrings) {
                totalOctets += octetString.octets.size
            }

            val string = ByteArray(totalOctets)
            var i = 0
            var pos = 0
            while (i < count) {
                val octets = octetStrings[i].octets
                octets.copyInto(string, pos, 0, octets.size)
                pos += octets.size
                ++i
            }

            //            assert pos == totalOctets;
            return string
        }
    }
}

fun fromByteArray(data: ByteArray): ASN1Primitive {
    val buffer = Buffer()
    buffer.write(data)
    val aIn = ASN1InputStream(object : Input {
        override fun read(
            buf: ByteArray,
            off: Int,
            len: Int
        ): Int {
            return buffer.readAtMostTo(buf, off, off + len)
        }

        override fun read(): Int {
            return buffer.readByte().toInt()
        }
    }, data.size)
    val o = aIn.readObject()
    /*
    if (aIn.input.available() != 0) {
        throw Exception("Extra data detected in stream")
    }
    aIn.input.close()*/
    return o!!
}

fun getTimeInstance(obj: Any): Time {
    return when (obj) {
        is Time -> obj
        is ASN1UTCTime -> Time(obj)
        is ASN1GeneralizedTime -> Time(obj)
        else -> {
            throw IllegalArgumentException("unknown object in factory")
        }
    }
}

fun getSequenceInstance(obj: Any): ASN1Sequence {
    return when (obj) {
        is ASN1Sequence -> {
            return obj
        }

        is ASN1Encodable -> {
            val primitive = obj.toASN1Primitive()
            if (primitive is ASN1Sequence) {
                return primitive
            } else {
                throw IllegalArgumentException("unknown object in getInstance ")
            }
        }

        is ByteArray -> {
            val primitive = fromByteArray(obj)
            primitive as? ASN1Sequence
                ?: throw IllegalArgumentException("failed to construct sequence from byte[] ")
        }

        else -> {
            throw IllegalArgumentException("unknown object in getInstance ")
        }
    }


}

fun getASN1ObjectIdentifierInstance(obj: Any): ASN1ObjectIdentifier {
    return when (obj) {
        is ASN1ObjectIdentifier -> {
            obj
        }

        is ASN1Encodable -> {
            val primitive = obj.toASN1Primitive()
            primitive as? ASN1ObjectIdentifier
                ?: throw IllegalArgumentException("failed to construct object identifier")
        }

        is ByteArray -> {
            val primitive = fromByteArray(obj)
            primitive as? ASN1ObjectIdentifier
                ?: throw IllegalArgumentException("failed to construct object identifier")
        }

        else -> {
            throw IllegalArgumentException("illegal object in getInstance: ")
        }
    }
}


fun getASN1BitStringInstance(obj: Any): ASN1BitString {
    return when (obj) {
        is ASN1BitString -> {
            return obj
        }

        is ASN1Encodable -> {
            val primitive = obj.toASN1Primitive()
            primitive as? ASN1BitString
                ?: throw IllegalArgumentException("illegal object in getInstance")
        }

        is ByteArray -> {
            val primitive = fromByteArray(obj)
            primitive as? ASN1BitString
                ?: throw IllegalArgumentException("failed to construct BIT STRING ")
        }

        else -> {
            throw IllegalArgumentException("illegal object in getInstance")
        }
    }
}


fun getASN1OctetStringInstance(obj: Any): ASN1OctetString {
    return when (obj) {
        is ASN1OctetString -> {
            return obj
        }

        is ASN1Encodable -> {
            val primitive = obj.toASN1Primitive()
            primitive as? ASN1OctetString
                ?: throw IllegalArgumentException("illegal object in getInstance")
        }

        is ByteArray -> {
            val primitive = fromByteArray(obj)
            primitive as? ASN1OctetString
                ?: throw IllegalArgumentException("failed to construct object ")
        }

        else -> {
            throw IllegalArgumentException("illegal object in getInstance")
        }
    }
}


val EMPTY_SEQUENCE: DLSequence = DLSequence()
private val EMPTY_SET = DLSet()


fun createSequence(v: ASN1EncodableVector): DLSequence {
    if (v.size() < 1) {
        return EMPTY_SEQUENCE
    }

    return DLSequence(v)
}


fun createSet(v: ASN1EncodableVector): DLSet {
    if (v.size() < 1) {
        return EMPTY_SET
    }

    return DLSet(v)
}

/**
 * Subject RDN components: telephone_number = 2.5.4.20
 */
val id_at_telephoneNumber: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.20").intern()

/**
 * Subject RDN components: name = 2.5.4.41
 */
val id_at_name: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.41").intern()

val id_at_organizationIdentifier: ASN1ObjectIdentifier =
    ASN1ObjectIdentifier("2.5.4.97").intern()


/**
 * Object identifiers for the various X9 standards.
 * <pre>
 * ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) ansi-x962(10045) }
</pre> *
 */
/**
 * Base OID: 1.2.840.10045
 */
val ansi_X9_62: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.10045")

/**
 * OID: 1.2.840.10045.4
 */
val id_ecSigType: ASN1ObjectIdentifier = ansi_X9_62.branch("4")

/**
 * OID: 1.2.840.10045.4.1
 */
val ecdsa_with_SHA1: ASN1ObjectIdentifier = id_ecSigType.branch("1")

/**
 * OID: 1.2.840.10045.4.3
 */
val ecdsa_with_SHA2: ASN1ObjectIdentifier = id_ecSigType.branch("3")

/**
 * OID: 1.2.840.10045.4.3.1
 */
val ecdsa_with_SHA224: ASN1ObjectIdentifier = ecdsa_with_SHA2.branch("1")

/**
 * OID: 1.2.840.10045.4.3.2
 */
val ecdsa_with_SHA256: ASN1ObjectIdentifier = ecdsa_with_SHA2.branch("2")

/**
 * OID: 1.2.840.10045.4.3.3
 */
val ecdsa_with_SHA384: ASN1ObjectIdentifier = ecdsa_with_SHA2.branch("3")

/**
 * OID: 1.2.840.10045.4.3.4
 */
val ecdsa_with_SHA512: ASN1ObjectIdentifier = ecdsa_with_SHA2.branch("4")


/**
 * pkcs-1 OBJECT IDENTIFIER ::=
 *
 *
 * { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
 */

/**
 * PKCS#1: 1.2.840.113549.1.1
 */
val pkcs_1: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113549.1.1")

/**
 * PKCS#1: 1.2.840.113549.1.1.10
 */
val id_RSASSA_PSS: ASN1ObjectIdentifier = pkcs_1.branch("10")

/**
 * PKCS#1: 1.2.840.113549.1.1.11
 */
val sha256WithRSAEncryption: ASN1ObjectIdentifier = pkcs_1.branch("11")

/**
 * PKCS#1: 1.2.840.113549.1.1.12
 */
val sha384WithRSAEncryption: ASN1ObjectIdentifier = pkcs_1.branch("12")

/**
 * PKCS#1: 1.2.840.113549.1.1.13
 */
val sha512WithRSAEncryption: ASN1ObjectIdentifier = pkcs_1.branch("13")

/**
 * PKCS#1: 1.2.840.113549.1.1.14
 */
val sha224WithRSAEncryption: ASN1ObjectIdentifier = pkcs_1.branch("14")


/**
 * PKCS#9: 1.2.840.113549.1.9
 */
val pkcs_9: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.113549.1.9")

/**
 * PKCS#9: 1.2.840.113549.1.9.1
 */
val pkcs_9_at_emailAddress: ASN1ObjectIdentifier = pkcs_9.branch("1").intern()

/**
 * PKCS#9: 1.2.840.113549.1.9.2
 */
val pkcs_9_at_unstructuredName: ASN1ObjectIdentifier = pkcs_9.branch("2").intern()

/**
 * PKCS#9: 1.2.840.113549.1.9.8
 */
val pkcs_9_at_unstructuredAddress: ASN1ObjectIdentifier = pkcs_9.branch("8").intern()


private val algorithms: Map<String, ASN1ObjectIdentifier> = mapOf(
    "SHA1WITHECDSA" to ecdsa_with_SHA1,
    "ECDSAWITHSHA1" to ecdsa_with_SHA1,
    "SHA224WITHECDSA" to ecdsa_with_SHA224,
    "SHA256WITHECDSA" to ecdsa_with_SHA256,
    "SHA384WITHECDSA" to ecdsa_with_SHA384,
    "SHA512WITHECDSA" to ecdsa_with_SHA512,
)

//
// According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
// The parameters field SHALL be NULL for RSA based signature algorithms.
//
private val noParams: Set<ASN1ObjectIdentifier> = setOf(
    ecdsa_with_SHA1,
    ecdsa_with_SHA224,
    ecdsa_with_SHA256,
    ecdsa_with_SHA384,
    ecdsa_with_SHA512,
)


private fun generate(signatureAlgorithm: String): AlgorithmIdentifier {
    val sigAlgId: AlgorithmIdentifier

    val algorithmName = toUpperCase(signatureAlgorithm)
    val sigOID = algorithms[algorithmName]
    requireNotNull(sigOID) { "Unknown signature payloadType requested: $algorithmName" }

    sigAlgId = if (noParams.contains(sigOID)) {
        AlgorithmIdentifier(sigOID)
    } else {
        AlgorithmIdentifier(sigOID, DERNull.INSTANCE)
    }

    return sigAlgId
}


fun find(sigAlgName: String): AlgorithmIdentifier {
    return generate(sigAlgName)
}

//
// reverse mappings
//
private val oids: Map<ASN1ObjectIdentifier, String> = mapOf(
    id_RSASSA_PSS to "RSASSA-PSS",
    ASN1ObjectIdentifier("1.2.840.113549.1.1.5") to "SHA1WITHRSA",
    sha224WithRSAEncryption to "SHA224WITHRSA",
    sha256WithRSAEncryption to "SHA256WITHRSA",
    sha384WithRSAEncryption to "SHA384WITHRSA",
    sha512WithRSAEncryption to "SHA512WITHRSA",
    ASN1ObjectIdentifier("1.2.840.113549.1.1.4") to "MD5WITHRSA",
    ASN1ObjectIdentifier("1.2.840.113549.1.1.2") to "MD2WITHRSA",
    ASN1ObjectIdentifier("1.2.840.10040.4.3") to "SHA1WITHDSA",
)

/**
 * Return the signature name for the passed in algorithm identifier. For signatures
 * that require parameters, like RSASSA-PSS, this is the best one to use.
 *
 * @param algorithmIdentifier the AlgorithmIdentifier of interest.
 * @return a string representation of the name.
 */

fun getAlgorithmName(algorithmIdentifier: AlgorithmIdentifier): String? {
    if (oids.containsKey(algorithmIdentifier.algorithm)) {
        return oids[algorithmIdentifier.algorithm]
    }

    return algorithmIdentifier.algorithm.id
}


fun toUTF8ByteArray(string: String): ByteArray {
    return toUTF8ByteArray(string.toCharArray())
}

private fun toUTF8ByteArray(string: CharArray): ByteArray {
    val bOut = Buffer()

    toUTF8ByteArray(string, bOut)


    return bOut.readByteArray()
}


private fun toUTF8ByteArray(string: CharArray, sOut: Buffer) {
    var i = 0

    while (i < string.size) {
        var ch = string[i]

        if (ch.code < 0x0080) {
            sOut.writeByte(ch.code.toByte())
        } else if (ch.code < 0x0800) {
            sOut.writeByte((0xc0 or (ch.code shr 6)).toByte())
            sOut.writeByte((0x80 or (ch.code and 0x3f)).toByte())
        } else if (ch.code in 0xD800..0xDFFF) {
            // in error - can only happen, if the Java String class has a
            // bug.
            check(i + 1 < string.size) { "invalid UTF-16 codepoint" }
            val w1 = ch
            ch = string[++i]
            val w2 = ch
            // in error - can only happen, if the Java String class has a
            // bug.
            check(w1.code <= 0xDBFF) { "invalid UTF-16 codepoint" }
            val codePoint = (((w1.code and 0x03FF) shl 10) or (w2.code and 0x03FF)) + 0x10000
            sOut.writeByte((0xf0 or (codePoint shr 18)).toByte())
            sOut.writeByte((0x80 or ((codePoint shr 12) and 0x3F)).toByte())
            sOut.writeByte((0x80 or ((codePoint shr 6) and 0x3F)).toByte())
            sOut.writeByte((0x80 or (codePoint and 0x3F)).toByte())
        } else {
            sOut.writeByte((0xe0 or (ch.code shr 12)).toByte())
            sOut.writeByte((0x80 or ((ch.code shr 6) and 0x3F)).toByte())
            sOut.writeByte((0x80 or (ch.code and 0x3F)).toByte())
        }

        i++
    }
}

/**
 * A locale independent version of toUpperCase.
 *
 * @param string input to be converted
 * @return a US Ascii uppercase version
 */
fun toUpperCase(string: String): String {
    var changed = false
    val chars = string.toCharArray()

    for (i in chars.indices) {
        val ch = chars[i]
        if (ch in 'a'..'z') {
            changed = true
            chars[i] = (ch.code - 'a'.code + 'A'.code).toChar()
        }
    }

    if (changed) {
        return chars.concatToString()
    }

    return string
}

/**
 * A locale independent version of toLowerCase.
 *
 * @param string input to be converted
 * @return a US ASCII lowercase version
 */
fun toLowerCase(string: String): String {
    var changed = false
    val chars = string.toCharArray()

    for (i in chars.indices) {
        val ch = chars[i]
        if (ch in 'A'..'Z') {
            changed = true
            chars[i] = (ch.code - 'A'.code + 'a'.code).toChar()
        }
    }

    if (changed) {
        return chars.concatToString()
    }

    return string
}


fun toByteArray(string: String): ByteArray {
    val bytes = ByteArray(string.length)

    for (i in bytes.indices) {
        val ch = string[i]

        bytes[i] = ch.code.toByte()
    }

    return bytes
}

/**
 * Fully read in len's bytes of data into buf, or up to EOF, whichever occurs first,
 *
 * @param inStr the stream to be read.
 * @param buf   the buffer to be read into.
 * @param off   offset into buf to start putting bytes into.
 * @param len   the number of bytes to be read.
 * @return the number of bytes read into the buffer.

 */

fun readFully(inStr: Input, buf: ByteArray, off: Int, len: Int): Int {
    var totalRead = 0
    while (totalRead < len) {
        val numRead = inStr.read(buf, off + totalRead, len - totalRead)
        if (numRead < 0) {
            break
        }
        totalRead += numRead
    }
    return totalRead
}

fun areArraysEqual(a: ByteArray, b: ByteArray?): Boolean {
    return a.contentEquals(b)
}


fun areArraysEqual(a: CharArray, b: CharArray?): Boolean {
    return a.contentEquals(b)
}


fun hashArrayCode(data: ByteArray?): Int {
    if (data == null) {
        return 0
    }

    var i = data.size
    var hc = i + 1

    while (--i >= 0) {
        hc *= 257
        hc = hc xor data[i].toInt()
    }

    return hc
}


fun cloneArray(data: ByteArray): ByteArray {
    return data.clone()
}


fun prepend(a: ByteArray?, b: Byte): ByteArray {
    if (a == null) {
        return byteArrayOf(b)
    }

    val length = a.size
    val result = ByteArray(length + 1)
    a.copyInto(result, 1, 0, length)
    result[0] = b
    return result
}


fun rDNsFromString(name: String, x500Style: X500NameStyle): Array<ASN1Encodable> {
    val nTok = X500NameTokenizer(name)
    val builder = X500NameBuilder(x500Style)

    while (nTok.hasMoreTokens()) {
        val token = nTok.nextToken()
        checkNotNull(token)

        val vTok = X500NameTokenizer(token, '=')

        val attr = vTok.nextToken()

        require(vTok.hasMoreTokens()) { "badly formatted directory string" }

        val value = vTok.nextToken()
        checkNotNull(attr)
        val oid = x500Style.attrNameToOID(attr.trim { it <= ' ' })
        checkNotNull(value)
        builder.addRDN(oid, value.trim { it <= ' ' })
    }


    return builder.build().rDNs()
}

fun decodeAttrName(
    name: String,
    lookUp: Map<String, ASN1ObjectIdentifier>
): ASN1ObjectIdentifier {
    if (toUpperCase(name).startsWith("OID.")) {
        return ASN1ObjectIdentifier(name.substring(4))
    } else if (name[0] in '0'..'9') {
        return ASN1ObjectIdentifier(name)
    }

    val oid = lookUp[toLowerCase(name)]
    requireNotNull(oid) { "Unknown object id - $name - passed to distinguished name" }

    return oid
}

