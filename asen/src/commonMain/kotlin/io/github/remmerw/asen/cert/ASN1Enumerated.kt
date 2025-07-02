package io.github.remmerw.asen.cert


/**
 * Class representing the ASN.1 ENUMERATED payloadType.
 */
class ASN1Enumerated private constructor(contents: ByteArray) : ASN1Primitive() {
    private val contents: ByteArray

    init {
        require(!ASN1Integer.isMalformed(contents)) { "malformed enumerated" }
        require(0 == (contents[0].toInt() and 0x80)) { "enumerated must be non-negative" }

        this.contents = cloneArray(contents)
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.ENUMERATED, contents)
    }

    override fun asn1Equals(
        other: ASN1Primitive
    ): Boolean {
        if (other !is ASN1Enumerated) {
            return false
        }

        return areArraysEqual(contents, other.contents)
    }

    companion object {
        private val cache = arrayOfNulls<ASN1Enumerated>(12)


        fun createPrimitive(contents: ByteArray): ASN1Enumerated {
            if (contents.size > 1) {
                return ASN1Enumerated(contents)
            }

            require(contents.isNotEmpty()) { "ENUMERATED has zero length" }
            val value = contents[0].toInt() and 0xff

            if (value >= cache.size) {
                return ASN1Enumerated(contents)
            }

            var possibleMatch = cache[value]

            if (possibleMatch == null) {
                cache[value] = ASN1Enumerated(contents)
                possibleMatch = cache[value]
            }

            return possibleMatch!!
        }
    }
}
