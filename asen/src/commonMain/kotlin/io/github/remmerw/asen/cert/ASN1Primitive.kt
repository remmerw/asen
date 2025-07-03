package io.github.remmerw.asen.cert

import kotlinx.io.Buffer
import kotlinx.io.Sink

/**
 * Base class for ASN.1 primitive objects. These are the actual objects used to generate byte encodings.
 */
abstract class ASN1Primitive : ASN1Object() {

    fun encodeTo(output: Sink) {
        val asn1Out = ASN1OutputStream(output)
        asn1Out.writePrimitive(this)
    }


    override fun encodeTo(output: Sink, encoding: String) {
        val asn1Out = createOutputStream(output, encoding)
        asn1Out.writePrimitive(this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        return (other is ASN1Encodable) && asn1Equals(other.toASN1Primitive())
    }

    fun equals(other: ASN1Primitive): Boolean {
        return this === other || asn1Equals(other)
    }

    override fun toASN1Primitive(): ASN1Primitive {
        return this
    }

    /**
     * Return the current object as one which encodes using Distinguished Encoding Rules.
     *
     * @return a DER version of this.
     */
    open fun toDERObject(): ASN1Primitive {
        return this
    }

    /**
     * Return the current object as one which encodes using Definite Length encoding.
     *
     * @return a DL version of this.
     */
    open fun toDLObject(): ASN1Primitive {
        return this
    }

    /**
     * Return true if this objected is a CONSTRUCTED one, false otherwise.
     *
     * @return true if CONSTRUCTED bit set on object's tag, false otherwise.
     */
    abstract fun encodeConstructed(): Boolean


    abstract fun encodedLength(withTag: Boolean): Int


    abstract fun encode(out: ASN1OutputStream, withTag: Boolean)

    /**
     * Equality (similarity) comparison for two ASN1Primitive objects.
     */
    abstract fun asn1Equals(other: ASN1Primitive): Boolean
    override fun hashCode(): Int {
        return this::class.hashCode()
    }

    companion object {
        /**
         * Create a base ASN.1 object from a byte stream.
         *
         * @param data the byte stream to parse.
         * @return the base ASN.1 object represented by the byte stream.
         */

        fun fromByteArray(data: ByteArray): ASN1Primitive {

            val buffer = Buffer()
            buffer.write(data)
            val aIn = ASN1InputStream(object : Input {
                override fun read(
                    buf: ByteArray,
                    off: Int,
                    len: Int
                ): Int {
                    return buffer.readAtMostTo(buf, off, off + len)
                }

                override fun read(): Int {
                    return buffer.readByte().toInt()
                }
            }, data.size)
            val o = aIn.readObject()

            /*
            if (aIn.input.available() != 0) {
                throw Exception("Extra data detected in stream")
            }
            aIn.input.close()*/
            return o!!

        }
    }
}