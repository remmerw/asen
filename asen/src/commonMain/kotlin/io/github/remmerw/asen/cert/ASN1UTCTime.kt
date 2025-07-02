package io.github.remmerw.asen.cert

/**
 * - * UTC time object.
 * Internal facade of [ASN1UTCTime].
 *
 *
 * This datatype is valid only from 1950-01-01 00:00:00 UTC until 2049-12-31 23:59:59 UTC.
 *
 * <hr></hr>
 *
 * **X.690**
 *
 * **11: Restrictions on BER employed by both CER and DER**
 *
 * **11.8 UTCTime **
 * **11.8.1** The encoding shall terminate with "Z",
 * as described in the ITU-T X.680 | ISO/IEC 8824-1 clause on UTCTime.
 *
 *
 * **11.8.2** The seconds element shall always be present.
 *
 *
 * **11.8.3** Midnight (GMT) shall be represented in the form:
 * <blockquote>
 * "YYMMDD000000Z"
</blockquote> *
 * where "YYMMDD" represents the day following the midnight in question.
 */
open class ASN1UTCTime : ASN1Primitive {
    private val contents: ByteArray

    /**
     * The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
     * never encoded. When you're creating one of these objects from scratch, that's
     * what you want to use, otherwise we'll try to deal with whatever gets read from
     * the input stream... (this is why the input format is different from the getTime()
     * method output).
     *
     *
     *
     * @param time the time string.
     */
    internal constructor(time: String) {
        this.contents = toByteArray(time)
    }

    private constructor(contents: ByteArray) {
        require(contents.size >= 2) { "UTCTime string too short" }
        this.contents = contents
        require(isDigit(0) && isDigit(1)) { "illegal characters in UTCTime string" }
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
        out.writeEncodingDL(withTag, BERTags.UTC_TIME, contents)
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1UTCTime) {
            return false
        }
        return areArraysEqual(contents, other.contents)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1UTCTime {
            return ASN1UTCTime(contents)
        }
    }
}
