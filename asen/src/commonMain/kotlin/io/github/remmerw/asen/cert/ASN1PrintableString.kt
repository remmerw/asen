package io.github.remmerw.asen.cert

/**
 * ASN.1 PrintableString object.
 *
 *
 * X.680 section 37.4 defines PrintableString character codes as ASCII subset of following characters:
 *
 *
 *  * Latin capital letters: 'A' .. 'Z'
 *  * Latin small letters: 'a' .. 'z'
 *  * Digits: '0'..'9'
 *  * Space
 *  * Apostrophe: '\''
 *  * Left parenthesis: '('
 *  * Right parenthesis: ')'
 *  * Plus sign: '+'
 *  * Comma: ','
 *  * Hyphen-minus: '-'
 *  * Full stop: '.'
 *  * Solidus: '/'
 *  * Colon: ':'
 *  * Equals sign: '='
 *  * Question mark: '?'
 *
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
abstract class ASN1PrintableString : ASN1Primitive, ASN1String {
    private val contents: ByteArray

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a PrintableString.
     */
    internal constructor(string: String) {
        require(isPrintableString(string)) { "string contains illegal characters" }

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
        out.writeEncodingDL(withTag, BERTags.PRINTABLE_STRING, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1PrintableString) {
            return false
        }

        return areArraysEqual(this.contents, other.contents)
    }


    companion object {
        /**
         * return true if the passed in String can be represented without
         * loss as a PrintableString, false otherwise.
         *
         * @return true if in printable set, false otherwise.
         */
        private fun isPrintableString(
            str: String
        ): Boolean {
            for (i in str.length - 1 downTo 0) {
                val ch = str[i]

                if (ch.code > 0x007f) {
                    return false
                }

                if (ch in 'a'..'z') {
                    continue
                }

                if (ch in 'A'..'Z') {
                    continue
                }

                if (ch in '0'..'9') {
                    continue
                }

                when (ch) {
                    ' ', '\'', '(', ')', '+', '-', '.', ':', '=', '?', '/', ',' -> {
                        continue
                    }
                }

                return false
            }

            return true
        }


        fun createPrimitive(contents: ByteArray): ASN1PrintableString {
            return DERPrintableString(contents)
        }
    }
}
