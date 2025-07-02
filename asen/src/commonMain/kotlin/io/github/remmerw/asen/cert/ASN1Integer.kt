package io.github.remmerw.asen.cert

import dev.whyoleg.cryptography.bigint.BigInt
import dev.whyoleg.cryptography.bigint.encodeToByteArray
import dev.whyoleg.cryptography.bigint.toBigInt
import kotlin.math.max

/**
 * Class representing the ASN.1 INTEGER payloadType.
 */
class ASN1Integer : ASN1Primitive {
    private val bytes: ByteArray
    private val start: Int

    /**
     * Construct an INTEGER from the passed in long value.
     *
     * @param value the long representing the value desired.
     */
    constructor(value: Long) {
        this.bytes = value.toBigInt().encodeToByteArray()
        this.start = 0
    }

    /**
     * Construct an INTEGER from the passed in BigInteger value.
     *
     * @param value the BigInteger representing the value desired.
     */
    constructor(value: BigInt) {
        this.bytes = value.encodeToByteArray()
        this.start = 0
    }

    constructor(bytes: ByteArray) {
        require(!isMalformed(bytes)) { "malformed integer" }

        this.bytes = bytes
        this.start = signBytesToSkip(bytes)
    }

    fun hasValue(x: Int): Boolean {
        return (bytes.size - start) <= 4
                && intValue(bytes, start) == x
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, bytes.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.INTEGER, bytes)
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1Integer) {
            return false
        }

        return areArraysEqual(this.bytes, other.bytes)
    }

    companion object {


        private const val SIGN_EXT_SIGNED = -0x1
        private const val SIGN_EXT_UNSIGNED = 0xFF

        /**
         * Return an integer from the passed in object.
         *
         * @param obj an ASN1Integer or an object that can be converted into one.
         * @return an ASN1Integer instance.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        fun getInstance(
            obj: Any
        ): ASN1Integer {
            if (obj is ASN1Integer) {
                return obj
            }

            if (obj is ByteArray) {
                try {
                    return fromByteArray(obj) as ASN1Integer
                } catch (e: Exception) {
                    throw IllegalArgumentException("encoding error in getInstance: $e")
                }
            }

            throw IllegalArgumentException("illegal object in getInstance")
        }

        /**
         * Return an Integer from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want

         * @return an ASN1Integer instance.
         * @throws IllegalArgumentException if the tagged object cannot
         * be converted.
         */
        fun getInstance(taggedObject: ASN1TaggedObject): ASN1Integer {
            return taggedObject.getBaseUniversal() as ASN1Integer
        }


        private fun intValue(bytes: ByteArray, start: Int): Int {
            val length = bytes.size
            var pos = max(start, (length - 4))

            var value = bytes[pos].toInt() and SIGN_EXT_SIGNED
            while (++pos < length) {
                value = (value shl 8) or (bytes[pos].toInt() and SIGN_EXT_UNSIGNED)
            }
            return value
        }

        /**
         * Apply the correct validation for an INTEGER primitive following the BER rules.
         *
         * @param bytes The raw encoding of the integer.
         * @return true if the (in)put fails this validation.
         */
        fun isMalformed(bytes: ByteArray): Boolean {
            return when (bytes.size) {
                0 -> true
                1 -> false
                else -> bytes[0].toInt() == (bytes[1].toInt() shr 7)
            }
        }

        private fun signBytesToSkip(bytes: ByteArray): Int {
            var pos = 0
            val last = bytes.size - 1
            while (pos < last
                && bytes[pos].toInt() == (bytes[pos + 1].toInt() shr 7)
            ) {
                ++pos
            }
            return pos
        }
    }
}
