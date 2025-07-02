package io.github.remmerw.asen.cert


/**
 * Carrier class for a DER encoding OCTET STRING
 */
class DEROctetString
    (string: ByteArray) : ASN1OctetString(string) {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, octets.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.OCTET_STRING, octets)
    }

    override fun toDERObject(): ASN1Primitive {
        return this
    }

    override fun toDLObject(): ASN1Primitive {
        return this
    }

    companion object {

        fun encode(out: ASN1OutputStream, withTag: Boolean, buf: ByteArray, off: Int, len: Int) {
            out.writeEncodingDL(withTag, BERTags.OCTET_STRING, buf, off, len)
        }

        fun encodedLength(withTag: Boolean, contentsLength: Int): Int {
            return getLengthOfEncodingDL(withTag, contentsLength)
        }
    }
}
