package io.github.remmerw.asen.cert

/**
 * ASN.1 IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
abstract class ASN1IA5String : ASN1Primitive, ASN1String {
    private val contents: ByteArray

    internal constructor(string: String) {
        require(isIA5String(string)) { "'string' contains illegal characters" }

        this.contents = toByteArray(string)
    }

    internal constructor(contents: ByteArray) {
        this.contents = contents
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.IA5_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1IA5String) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }

    companion object {
        /**
         * return true if the passed in String can be represented without
         * loss as an IA5String, false otherwise.
         *
         * @param str the string to check.
         * @return true if character set in IA5String set, false otherwise.
         */
        private fun isIA5String(str: String): Boolean {
            for (i in str.length - 1 downTo 0) {
                val ch = str[i]
                if (ch.code > 0x007f) {
                    return false
                }
            }

            return true
        }

        fun createPrimitive(contents: ByteArray): ASN1IA5String {
            return DERIA5String(contents)
        }
    }
}
