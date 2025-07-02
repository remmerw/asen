package io.github.remmerw.asen.cert


/**
 * The DLSequence encodes a SEQUENCE using definite length form.
 */
class DLSequence : ASN1Sequence {
    private var contentsLength = -1

    /**
     * Create an empty sequence
     */
    constructor()

    /**
     * create a sequence containing a vector of objects.
     *
     * @param elementVector the vector of objects to make up the sequence.
     */
    constructor(elementVector: ASN1EncodableVector) : super(elementVector)

    /**
     * create a sequence containing an array of objects.
     *
     * @param elements the array of objects to make up the sequence.
     */
    constructor(elements: Array<ASN1Encodable>) : super(elements)


    private fun getContentsLength(): Int {
        if (contentsLength < 0) {
            var totalLength = 0

            for (element in elements) {
                val dlObject = element.toASN1Primitive().toDLObject()
                totalLength += dlObject.encodedLength(true)
            }

            this.contentsLength = totalLength
        }

        return contentsLength
    }


    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, getContentsLength())
    }

    /**
     * A note on the implementation:
     *
     *
     * As DL requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.SEQUENCE)

        val dlOut: ASN1OutputStream = out.dLSubStream()

        val count = elements.size
        if (contentsLength >= 0 || count > 16) {
            out.writeDL(getContentsLength())

            for (element in elements) {
                dlOut.writePrimitive(element.toASN1Primitive())
            }
        } else {
            var totalLength = 0

            val dlObjects = arrayOfNulls<ASN1Primitive>(count)
            for (i in 0 until count) {
                val dlObject = elements[i].toASN1Primitive().toDLObject()
                dlObjects[i] = dlObject
                totalLength += dlObject.encodedLength(true)
            }

            this.contentsLength = totalLength
            out.writeDL(totalLength)

            for (i in 0 until count) {
                dlOut.writePrimitive(dlObjects[i]!!)
            }
        }
    }

    override fun toDLObject(): ASN1Primitive {
        return this
    }
}
