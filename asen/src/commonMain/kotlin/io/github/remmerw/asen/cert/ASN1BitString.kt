package io.github.remmerw.asen.cert


/**
 * Base class for BIT STRING objects
 */
abstract class ASN1BitString : ASN1Primitive, ASN1String, ASN1Encodable {

    val contents: ByteArray

    /**
     * Base constructor.
     *
     * @param data    the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    internal constructor(data: ByteArray, padBits: Int) {
        require(!(data.isEmpty() && padBits != 0)) { "zero length data with non-zero pad bits" }
        require(!(padBits !in 0..7)) { "pad bits cannot be greater than 7 or less than 0" }

        this.contents = prepend(data, padBits.toByte())
    }

    internal constructor(contents: ByteArray) {
        this.contents = contents
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1BitString) {
            return false
        }

        val thisContents = this.contents
        val thatContents = other.contents

        val length = thisContents.size
        if (thatContents.size != length) {
            return false
        }
        if (length == 1) {
            return true
        }

        val last = length - 1
        for (i in 0 until last) {
            if (thisContents[i] != thatContents[i]) {
                return false
            }
        }

        val padBits = thisContents[0].toInt() and 0xFF
        val thisLastOctetDER = (thisContents[last].toInt() and (0xFF shl padBits)).toByte()
        val thatLastOctetDER = (thatContents[last].toInt() and (0xFF shl padBits)).toByte()

        return thisLastOctetDER == thatLastOctetDER
    }

    override fun toDERObject(): ASN1Primitive {
        return DERBitString(contents)
    }

    override fun toDLObject(): ASN1Primitive {
        return DLBitString(contents)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1BitString {
            val length = contents.size
            require(length >= 1) { "truncated BIT STRING detected" }

            val padBits = contents[0].toInt() and 0xFF
            if (padBits > 0) {
                require(!(padBits > 7 || length < 2)) { "invalid pad bits detected" }

                val finalOctet = contents[length - 1]
                if (finalOctet != (finalOctet.toInt() and (0xFF shl padBits)).toByte()) {
                    return DLBitString(contents)
                }
            }

            return DERBitString(contents)
        }
    }
}
