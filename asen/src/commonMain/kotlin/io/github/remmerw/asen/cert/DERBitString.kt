package io.github.remmerw.asen.cert


/**
 * A BIT STRING with DER encoding - the first byte contains the count of padding bits included in the byte array's last byte.
 */
class DERBitString : ASN1BitString {
    constructor(data: ByteArray, padBits: Int) : super(data, padBits)

    internal constructor(contents: ByteArray) : super(contents)

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        val padBits = contents[0].toInt() and 0xFF
        val length = contents.size
        val last = length - 1

        val lastOctet = contents[last]
        val lastOctetDER = (contents[last].toInt() and (0xFF shl padBits)).toByte()

        if (lastOctet == lastOctetDER) {
            out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents)
        } else {
            out.writeEncodingDL(withTag, contents, last, lastOctetDER)
        }
    }

    override fun toDERObject(): ASN1Primitive {
        return this
    }

    override fun toDLObject(): ASN1Primitive {
        return this
    }
}
