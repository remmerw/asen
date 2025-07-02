package io.github.remmerw.asen.cert

/**
 * Holding class for a single Relative Distinguished Name (RDN).
 */
class RDN internal constructor(oid: ASN1ObjectIdentifier?, value: ASN1Encodable?) : ASN1Object() {
    private val values: ASN1Set


    init {
        val v = ASN1EncodableVector()

        v.add(oid!!)
        v.add(value!!)

        this.values = DERSet(DERSequence(v))
    }


    /**
     * <pre>
     * RelativeDistinguishedName ::=
     * SET OF AttributeTypeAndValue
     *
     * AttributeTypeAndValue ::= SEQUENCE {
     * payloadType     AttributeType,
     * value    AttributeValue }
    </pre> *
     *
     * @return this object as its ASN1Primitive payloadType
     */
    override fun toASN1Primitive(): ASN1Primitive {
        return values
    }
}
