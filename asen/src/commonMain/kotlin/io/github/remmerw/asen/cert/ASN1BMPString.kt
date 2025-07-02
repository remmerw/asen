package io.github.remmerw.asen.cert

/**
 * ASN.1 BMPString object encodes BMP (*Basic Multilingual Plane*) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 *
 *
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 *
 */
abstract class ASN1BMPString internal constructor(private val string: CharArray) : ASN1Primitive(),
    ASN1String {

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1BMPString) {
            return false
        }

        return areArraysEqual(this.string, other.string)
    }


    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, string.size * 2)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        val count = string.size

        out.writeIdentifier(withTag, BERTags.BMP_STRING)
        out.writeDL(count * 2)

        val buf = ByteArray(8)

        var i = 0
        val limit = count and -4
        while (i < limit) {
            val c0 = string[i]
            val c1 = string[i + 1]
            val c2 = string[i + 2]
            val c3 = string[i + 3]
            i += 4

            buf[0] = (c0.code shr 8).toByte()
            buf[1] = c0.code.toByte()
            buf[2] = (c1.code shr 8).toByte()
            buf[3] = c1.code.toByte()
            buf[4] = (c2.code shr 8).toByte()
            buf[5] = c2.code.toByte()
            buf[6] = (c3.code shr 8).toByte()
            buf[7] = c3.code.toByte()

            out.write(buf, 0, 8)
        }
        if (i < count) {
            var bufPos = 0
            do {
                val c0 = string[i]
                i += 1

                buf[bufPos++] = (c0.code shr 8).toByte()
                buf[bufPos++] = c0.code.toByte()
            } while (i < count)

            out.write(buf, 0, bufPos)
        }
    }

}
