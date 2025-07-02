package io.github.remmerw.asen.cert

/**
 * ASN.1 GENERAL-STRING data payloadType.
 *
 *
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 *
 */
abstract class ASN1GeneralString internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.GENERAL_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1GeneralString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    companion object {
        fun createPrimitive(contents: ByteArray): ASN1GeneralString {
            return DERGeneralString(contents)
        }
    }
}
