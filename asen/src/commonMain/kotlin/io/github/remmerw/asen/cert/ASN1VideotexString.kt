package io.github.remmerw.asen.cert


abstract class ASN1VideotexString internal constructor(private val contents: ByteArray) :
    ASN1Primitive(),
    ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.VIDEOTEX_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1VideotexString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }


    companion object {

        fun createPrimitive(contents: ByteArray): ASN1VideotexString {
            return DERVideotexString(contents)
        }
    }
}
