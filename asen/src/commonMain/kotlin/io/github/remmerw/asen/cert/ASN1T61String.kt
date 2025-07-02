package io.github.remmerw.asen.cert


/**
 * ASN.1 T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
abstract class ASN1T61String internal constructor(private val contents: ByteArray) :
    ASN1Primitive(), ASN1String {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.T61_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1T61String) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    companion object {
        fun createPrimitive(contents: ByteArray): ASN1T61String {
            return DERT61String(contents)
        }
    }
}
