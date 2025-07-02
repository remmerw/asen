package io.github.remmerw.asen.cert

abstract class ASN1UTF8String internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    internal constructor(string: String) : this(toUTF8ByteArray(string))

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1UTF8String) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.UTF8_STRING, contents)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1UTF8String {
            return DERUTF8String(contents)
        }
    }
}
