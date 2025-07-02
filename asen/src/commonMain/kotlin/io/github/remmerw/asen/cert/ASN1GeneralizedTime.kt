package io.github.remmerw.asen.cert

/**
 * Base class representing the ASN.1 GeneralizedTime payloadType.
 *
 *
 * The main difference between these and UTC time is a 4 digit year.
 *
 *
 *
 * One second resolution date+time on UTC timezone (Z)
 * with 4 digit year (valid from 0001 to 9999).
 *
 * Timestamp format is:  yyyymmddHHMMSS'Z'
 * <h2>X.690</h2>
 * This is what is called "restricted string",
 * and it uses ASCII characters to encode digits and supplemental data.
 *
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.7 GeneralizedTime </h4>
 *
 *
 * **11.7.1** The encoding shall terminate with a "Z",
 * as described in the ITU-T Rec. X.680 | ISO/IEC 8824-1 clause on
 * GeneralizedTime.
 *
 *
 * **11.7.2** The seconds element shall always be present.
 *
 *
 *
 * **11.7.3** The fractional-seconds elements, if present,
 * shall omit all trailing zeros; if the elements correspond to 0,
 * they shall be wholly omitted, and the decimal point element also
 * shall be omitted.
 */
open class ASN1GeneralizedTime : ASN1Primitive {
    val contents: ByteArray

    /**
     * The correct format for this is YYYYMMDDHHMMSS[.f]Z, or without the Z
     * for local time, or Z+-HHMM on the end, for difference between local
     * time and UTC time. The fractional second amount f must consist of at
     * least one number with trailing zeroes removed.
     *
     * @param time the time string.
     * @throws IllegalArgumentException if String is an illegal format.
     */
    constructor(time: String) {
        this.contents = toByteArray(time)
    }

    internal constructor(bytes: ByteArray) {
        require(bytes.size >= 4) { "GeneralizedTime string too short" }
        this.contents = bytes

        require(isDigit(0) && isDigit(1) && isDigit(2) && isDigit(3)) { "illegal characters in GeneralizedTime string" }
    }

    fun hasFractionalSeconds(): Boolean {
        for (i in contents.indices) {
            if (contents[i] == '.'.code.toByte()) {
                if (i == 14) {
                    return true
                }
            }
        }
        return false
    }

    fun hasSeconds(): Boolean {
        return isDigit(12) && isDigit(13)
    }

    fun hasMinutes(): Boolean {
        return isDigit(10) && isDigit(11)
    }

    private fun isDigit(pos: Int): Boolean {
        return contents.size > pos && contents[pos] >= '0'.code.toByte() && contents[pos] <= '9'.code.toByte()
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.GENERALIZED_TIME, contents)
    }

    override fun toDERObject(): ASN1Primitive {
        return DERGeneralizedTime(contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1GeneralizedTime) {
            return false
        }

        return areArraysEqual(contents, other.contents)
    }

    companion object {
        fun createPrimitive(contents: ByteArray): ASN1GeneralizedTime {
            return ASN1GeneralizedTime(contents)
        }
    }
}
