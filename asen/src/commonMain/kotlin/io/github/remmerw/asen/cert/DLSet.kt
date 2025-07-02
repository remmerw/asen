package io.github.remmerw.asen.cert


/**
 * The DLSet encodes ASN.1 SET value without element ordering,
 * and always using definite length form.
 * <hr></hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.11 Encoding of a set value </h4>
 * **8.11.1** The encoding of a set value shall be constructed
 *
 *
 * **8.11.2** The contents octets shall consist of the complete
 * encoding of a data value from each of the types listed in the
 * ASN.1 definition of the set payloadType, in an order chosen by the sender,
 * unless the payloadType was referenced with the keyword
 * **OPTIONAL** or the keyword **DEFAULT**.
 *
 *
 * **8.11.3** The encoding of a data value may, but need not,
 * be present for a payloadType which was referenced with the keyword
 * **OPTIONAL** or the keyword **DEFAULT**.
 * <blockquote>
 * NOTE  The order of data values in a set value is not significant,
 * and places no constraints on the order during transfer
</blockquote> *
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.3 Set components</h4>
 * The encodings of the component values of a set value shall
 * appear in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * Additionally, for the purposes of determining the order in which
 * components are encoded when one or more component is an untagged
 * choice payloadType, each untagged choice payloadType is ordered as though it
 * has a tag equal to that of the smallest tag in that choice payloadType
 * or any untagged choice types nested within.
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.3 Set components</h4>
 * The encodings of the component values of a set value shall appear
 * in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <blockquote>
 * NOTE  Where a component of the set is an untagged choice payloadType,
 * the location of that component in the ordering will depend on
 * the tag of the choice component being encoded.
</blockquote> *
 * <h4>11.5 Set and sequence components with default value </h4>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 */
class DLSet : ASN1Set {
    private var contentsLength = -1

    /**
     * create an empty set
     */
    constructor()

    /**
     * @param elementVector - a vector of objects making up the set.
     */
    constructor(elementVector: ASN1EncodableVector) : super(elementVector)


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
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.SET)

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
}