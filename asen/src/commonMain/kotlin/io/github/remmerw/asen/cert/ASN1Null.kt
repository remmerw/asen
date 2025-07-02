package io.github.remmerw.asen.cert

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
abstract class ASN1Null : ASN1Primitive() {
    override fun asn1Equals(other: ASN1Primitive): Boolean {
        return other is ASN1Null
    }

}
