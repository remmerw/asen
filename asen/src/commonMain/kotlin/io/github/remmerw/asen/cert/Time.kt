package io.github.remmerw.asen.cert

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter


class Time : ASN1Object, ASN1Choice {
    private val time: ASN1Primitive

    internal constructor(time: ASN1Primitive) {
        require(!(time !is ASN1UTCTime && time !is ASN1GeneralizedTime)) { "unknown object passed to Time" }

        this.time = time
    }

    /**
     * Creates a time object from a given date and locale - if the date is between 1950
     * and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
     * is used. You may need to use this constructor if the default locale
     * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
     *
     * @param time   a date object representing the time of interest.
     */
    constructor(time: LocalDateTime) {
        val formatPattern = "yyyyMMddHHmmss"


        val format = DateTimeFormatter.ofPattern(formatPattern)

        val d = time.format(format) + "Z"
        val year = d.substring(0, 4).toInt()

        if (year !in 1950..2049) {
            this.time = DERGeneralizedTime(d)
        } else {
            this.time = DERUTCTime(d.substring(2))
        }
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Time ::= CHOICE {
     * utcTime        UTCTime,
     * generalTime    GeneralizedTime }
    </pre> *
     */
    override fun toASN1Primitive(): ASN1Primitive {
        return time
    }
}
