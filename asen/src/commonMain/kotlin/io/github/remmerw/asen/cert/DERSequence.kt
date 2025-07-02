package io.github.remmerw.asen.cert


/**
 * Definite length SEQUENCE, encoding tells explicit number of bytes
 * that the content of this sequence occupies.
 *
 *
 * For X.690 syntax rules, see [ASN1Sequence].
 */
class DERSequence : ASN1Sequence {
    private var contentsLength = -1

    /**
     * Create an empty sequence
     */
    constructor()

    /**
     * Create a sequence containing a vector of objects.
     *
     * @param elementVector the vector of objects to make up the sequence.
     */
    constructor(elementVector: ASN1EncodableVector) : super(elementVector)

    /**
     * Create a sequence containing an array of objects.
     *
     * @param elements the array of objects to make up the sequence.
     */
    constructor(elements: Array<ASN1Encodable>) : super(elements)


    private fun getContentsLength(): Int {
        if (contentsLength < 0) {
            var totalLength = 0

            for (element in elements) {
                val derObject = element.toASN1Primitive().toDERObject()
                totalLength += derObject.encodedLength(true)
            }

            this.contentsLength = totalLength
        }

        return contentsLength
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, getContentsLength())
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.SEQUENCE)

        val derOut = out.dERSubStream()

        val count = elements.size
        if (contentsLength >= 0 || count > 16) {
            out.writeDL(getContentsLength())

            for (element in elements) {
                val derObject = element.toASN1Primitive().toDERObject()
                derObject.encode(derOut, true)
            }
        } else {
            var totalLength = 0

            val derObjects = arrayOfNulls<ASN1Primitive>(count)
            for (i in 0 until count) {
                val derObject = elements[i].toASN1Primitive().toDERObject()
                derObjects[i] = derObject
                totalLength += derObject.encodedLength(true)
            }

            this.contentsLength = totalLength
            out.writeDL(totalLength)

            for (i in 0 until count) {
                derObjects[i]!!.encode(derOut, true)
            }
        }
    }


    override fun toDERObject(): ASN1Primitive {
        return this
    }

    override fun toDLObject(): ASN1Primitive {
        return this
    }

}
