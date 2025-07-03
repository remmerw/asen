package io.github.remmerw.asen.cert


class ASN1RelativeOID(contents: ByteArray) : ASN1Primitive() {
    private val identifier: String
    private val contents: ByteArray

    init {
        val objId = StringBuilder()
        var value: Long = 0

        var first = true

        for (i in contents.indices) {
            val b = contents[i].toInt() and 0xff

            require(value <= LONG_LIMIT) { "out of supported range" }
            value += (b and 0x7F).toLong()
            if ((b and 0x80) == 0) {
                if (first) {
                    first = false
                } else {
                    objId.append('.')
                }

                objId.append(value)
                value = 0
            } else {
                value = value shl 7
            }

        }

        this.identifier = objId.toString()
        this.contents = contents
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (this === other) {
            return true
        }
        if (other !is ASN1RelativeOID) {
            return false
        }

        return this.identifier == other.identifier
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.RELATIVE_OID, contents)
    }

    override fun encodeConstructed(): Boolean {
        return false
    }
}
