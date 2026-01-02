package io.github.remmerw.asen.cert

/**
 * Basic interface to produce serializers for ASN.1 encodings.
 */
interface ASN1Encodable {
    /**
     * Return an object, possibly constructed, of ASN.1 primitives
     *
     * @return an ASN.1 primitive.
     */
    fun toASN1Primitive(): ASN1Primitive
}
