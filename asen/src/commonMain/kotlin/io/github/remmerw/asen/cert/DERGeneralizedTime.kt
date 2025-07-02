package io.github.remmerw.asen.cert

/**
 * DER Generalized time object.
 * 11: Restrictions on BER employed by both CER and DER
 * 11.7 GeneralizedTime
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
class DERGeneralizedTime : ASN1GeneralizedTime {
    constructor(time: ByteArray) : super(time)

    constructor(time: String) : super(time)

    private val dERTime: ByteArray
        get() {
            if (contents[contents.size - 1] == 'Z'.code.toByte()) {
                if (!hasMinutes()) {
                    val derTime = ByteArray(contents.size + 4)
                    contents.copyInto(derTime, 0, 0, contents.size - 1)

                    toByteArray("0000Z").copyInto(derTime, contents.size - 1, 0, 5)

                    return derTime
                } else if (!hasSeconds()) {
                    val derTime = ByteArray(contents.size + 2)
                    contents.copyInto(derTime, 0, 0, contents.size - 1)


                    toByteArray("00Z").copyInto(derTime, contents.size - 1, 0, 3)

                    return derTime
                } else if (hasFractionalSeconds()) {
                    var ind = contents.size - 2
                    while (ind > 0 && contents[ind] == '0'.code.toByte()) {
                        ind--
                    }

                    val derTime: ByteArray
                    if (contents[ind] == '.'.code.toByte()) {
                        derTime = ByteArray(ind + 1)

                        contents.copyInto(derTime, 0, 0, ind)

                        derTime[ind] = 'Z'.code.toByte()
                    } else {
                        derTime = ByteArray(ind + 2)

                        contents.copyInto(derTime, 0, 0, ind + 1)
                        derTime[ind + 1] = 'Z'.code.toByte()
                    }
                    return derTime
                } else {
                    return contents
                }
            } else {
                return contents
            }
        }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, dERTime.size)
    }

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.GENERALIZED_TIME, dERTime)
    }

    override fun toDERObject(): ASN1Primitive {
        return this
    }
}
