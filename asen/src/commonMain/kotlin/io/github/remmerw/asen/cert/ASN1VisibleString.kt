package io.github.remmerw.asen.cert


/**
 * ASN.1 VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
abstract class ASN1VisibleString internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.VISIBLE_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1VisibleString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1VisibleString {
            return DERVisibleString(contents)
        }
    }
}
