package io.github.remmerw.asen.cert

/**
 * ASN.1 UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
abstract class ASN1UniversalString internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.UNIVERSAL_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1UniversalString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1UniversalString {
            return DERUniversalString(contents)
        }
    }
}
