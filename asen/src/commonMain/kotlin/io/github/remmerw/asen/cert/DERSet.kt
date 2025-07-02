package io.github.remmerw.asen.cert


/**
 * A DER encoded SET object
 *
 *
 * For X.690 syntax rules, see [ASN1Set].
 *
 *
 * For short: Constructing this form does sort the supplied elements,
 * and the sorting happens also before serialization (if necesssary).
 * This is different from the way  does things.
 *
 */
class DERSet : ASN1Set {
    private var contentsLength = -1

    /**
     * create a set containing one object
     *
     * @param element the object to go in the set
     */
    constructor(element: ASN1Encodable) : super(element)

    /**
     * create a set containing an array of objects.
     *
     * @param elements the array of objects to make up the set.
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
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */

    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.SET)

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
        return if (isSorted) this else super.toDERObject()
    }
}
