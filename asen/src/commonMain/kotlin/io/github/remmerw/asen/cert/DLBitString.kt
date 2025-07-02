package io.github.remmerw.asen.cert


/**
 * A Definite length BIT STRING
 */
internal class DLBitString(contents: ByteArray) : ASN1BitString(contents) {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents)
    }

    override fun toDLObject(): ASN1Primitive {
        return this
    }

}
