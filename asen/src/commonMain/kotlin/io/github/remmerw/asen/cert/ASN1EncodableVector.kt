package io.github.remmerw.asen.cert

/**
 * Mutable class for building ASN.1 constructed objects such as SETs or SEQUENCEs.
 */
class ASN1EncodableVector {
    private var elements: MutableList<ASN1Encodable> = mutableListOf()

    fun add(element: ASN1Encodable) {
        elements.add(element)
    }

    /**
     * Return the object at position i in this vector.
     *
     * @param i the index of the object of interest.
     * @return the object at position i.
     */
    fun get(i: Int): ASN1Encodable {
        return elements[i]
    }

    /**
     * Return the size of the vector.
     *
     * @return the object count in the vector.
     */
    fun size(): Int {
        return elements.size
    }

    fun takeElements(): Array<ASN1Encodable> {

        return elements.toTypedArray().copyOf()
    }


    companion object {
        val EMPTY_ELEMENTS: Array<ASN1Encodable> = emptyArray()
    }
}
