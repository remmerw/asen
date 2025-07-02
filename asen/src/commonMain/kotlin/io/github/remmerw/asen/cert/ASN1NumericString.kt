package io.github.remmerw.asen.cert


/**
 * NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 *
 *
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 *
 *
 * See X.680 section 37.2.
 *
 *
 * Explicit character set escape sequences are not allowed.
 */
abstract class ASN1NumericString internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.NUMERIC_STRING, contents)
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1NumericString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }
}
