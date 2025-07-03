package io.github.remmerw.asen.cert

/**
 * ASN.1 `SEQUENCE` and `SEQUENCE OF` constructs.
 *
 *
 * DER form is always definite form length fields, while
 * BER support uses indefinite form.
 * <hr></hr>
 *
 * **X.690**
 *
 * **8: Basic encoding rules**
 *
 * **8.9 Encoding of a sequence value **
 * 8.9.1 The encoding of a sequence value shall be constructed.
 *
 *
 * **8.9.2** The contents octets shall consist of the complete
 * encoding of one data value from each of the types listed in
 * the ASN.1 definition of the sequence payloadType, in the order of
 * their appearance in the definition, unless the payloadType was referenced
 * with the keyword **OPTIONAL** or the keyword **DEFAULT**.
 *
 *
 * **8.9.3** The encoding of a data value may, but need not,
 * be present for a payloadType which was referenced with the keyword
 * **OPTIONAL** or the keyword **DEFAULT**.
 * If present, it shall appear in the encoding at the point
 * corresponding to the appearance of the payloadType in the ASN.1 definition.
 *
 *
 * **8.10 Encoding of a sequence-of value **
 *
 *
 * **8.10.1** The encoding of a sequence-of value shall be constructed.
 *
 *
 * **8.10.2** The contents octets shall consist of zero,
 * one or more complete encodings of data values from the payloadType listed in
 * the ASN.1 definition.
 *
 *
 * **8.10.3** The order of the encodings of the data values shall be
 * the same as the order of the data values in the sequence-of value to
 * be encoded.
 *
 *
 * **9: Canonical encoding rules**
 *
 * **9.1 Length forms**
 * If the encoding is constructed, it shall employ the indefinite-length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 *
 *
 * **11: Restrictions on BER employed by both CER and DER**
 *
 * **11.5 Set and sequence components with default value**
 *
 *
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 *
 */
abstract class ASN1Sequence : ASN1Primitive {
    var elements: Array<ASN1Encodable>

    /**
     * Create an empty SEQUENCE
     */
    internal constructor() {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS
    }

    /**
     * Create a SEQUENCE containing a vector of objects.
     *
     * @param elementVector the vector of objects to be put in the SEQUENCE.
     */
    internal constructor(elementVector: ASN1EncodableVector) {

        this.elements = elementVector.takeElements()
    }

    /**
     * Create a SEQUENCE containing an array of objects.
     *
     * @param elements the array of objects to be put in the SEQUENCE.
     */
    internal constructor(elements: Array<ASN1Encodable>) {

        this.elements = elements.copyOf()
    }

    fun toArrayInternal(): Array<ASN1Encodable> {
        return elements
    }


    /**
     * Return the object at the sequence position indicated by index.
     *
     * @param index the sequence number (starting at zero) of the object
     * @return the object at the sequence position indicated by index.
     */
    fun getObjectAt(index: Int): ASN1Encodable {
        return elements[index]
    }

    /**
     * Return the number of objects in this sequence.
     *
     * @return the number of objects in this sequence.
     */
    fun size(): Int {
        return elements.size
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1Sequence) {
            return false
        }

        // NOTE: Call size() here (on both) to 'force' a LazyEncodedSequence
        val count = this.size()
        if (other.size() != count) {
            return false
        }

        for (i in 0 until count) {
            val p1 = elements[i].toASN1Primitive()
            val p2 = other.elements[i].toASN1Primitive()

            if (p1 !== p2 && !p1.asn1Equals(p2)) {
                return false
            }
        }

        return true
    }

    /**
     * Change current SEQUENCE object to be encoded as [DERSequence].
     * This is part of Distinguished Encoding Rules form serialization.
     */
    override fun toDERObject(): ASN1Primitive {
        return DERSequence(elements)
    }

    /**
     * Change current SEQUENCE object to be encoded as [DLSequence].
     * This is part of Direct Length form serialization.
     */
    override fun toDLObject(): ASN1Primitive {
        return DLSequence(elements)
    }

    override fun encodeConstructed(): Boolean {
        return true
    }


    companion object {

        /**
         * Return an ASN1 SEQUENCE from a tagged object. There is a special
         * case here, if an object appears to have been explicitly tagged on
         * reading but we were expecting it to be implicitly tagged in the
         * normal course of events it indicates that we lost the surrounding
         * sequence - so we need to add it back (this will happen if the tagged
         * object is a sequence that contains other sequences). If you are
         * dealing with implicitly tagged sequences you really **should**
         * be using this method.
         *
         * @param taggedObject the tagged object.
         * @return an ASN1Sequence instance.
         * @throws IllegalArgumentException if the tagged object cannot
         * be converted.
         */
        fun getInstance(taggedObject: ASN1TaggedObject): ASN1Sequence {
            return taggedObject.getBaseUniversal() as ASN1Sequence
        }
    }
}
