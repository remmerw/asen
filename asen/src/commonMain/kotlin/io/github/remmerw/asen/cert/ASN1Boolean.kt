package io.github.remmerw.asen.cert


/**
 * Public facade of ASN.1 Boolean data.
 *
 *
 * Use following to place a new instance of ASN.1 Boolean in your data:
 *
 *  *  ASN1Boolean.TRUE literal
 *  *  ASN1Boolean.FALSE literal
 *
 */
class ASN1Boolean private constructor(private val value: Byte) : ASN1Primitive() {
    val isTrue: Boolean
        get() = value != FALSE_VALUE

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, 1)
    }

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, value)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1Boolean) {
            return false
        }

        return this.isTrue == other.isTrue
    }

    override fun toDERObject(): ASN1Primitive {
        return if (isTrue) TRUE else FALSE
    }


    companion object {
        private const val FALSE_VALUE: Byte = 0x00
        private val FALSE = ASN1Boolean(FALSE_VALUE)
        private const val TRUE_VALUE = 0xFF.toByte()
        private val TRUE = ASN1Boolean(TRUE_VALUE)

        /**
         * Return a boolean from the passed in object.
         *
         * @param obj an ASN1Boolean or an object that can be converted into one.
         * @return an ASN1Boolean instance.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        fun getInstance(
            obj: Any?
        ): ASN1Boolean {
            if (obj == null || obj is ASN1Boolean) {
                return obj as ASN1Boolean
            }

            if (obj is ByteArray) {
                try {
                    return fromByteArray(obj) as ASN1Boolean
                } catch (e: Exception) {
                    throw IllegalArgumentException("failed to construct boolean from byte[]: " + e.message)
                }
            }

            throw IllegalArgumentException("illegal object in getInstance")
        }

        /**
         * Return an ASN1Boolean from the passed in boolean.
         *
         * @param value true or false depending on the ASN1Boolean wanted.
         * @return an ASN1Boolean instance.
         */
        fun getInstance(value: Boolean): ASN1Boolean {
            return if (value) TRUE else FALSE
        }

        fun createPrimitive(contents: ByteArray): ASN1Boolean {
            require(contents.size == 1) { "BOOLEAN value should have 1 byte in it" }

            return when (val b = contents[0]) {
                FALSE_VALUE -> FALSE
                TRUE_VALUE -> TRUE
                else -> ASN1Boolean(b)
            }
        }
    }
}
