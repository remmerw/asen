package io.github.remmerw.asen.cert


/**
 * An ASN.1 DER NULL object.
 *
 *
 * Preferably use the constant:  DERNull.INSTANCE.
 */
class DERNull private constructor() : ASN1Null() {
    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, 0)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.NULL, ZERO_BYTES)
    }

    companion object {
        val INSTANCE: DERNull = DERNull()
    }
}
