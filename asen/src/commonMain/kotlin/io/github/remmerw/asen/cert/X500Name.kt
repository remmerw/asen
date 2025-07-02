package io.github.remmerw.asen.cert

/**
 * The X.500 Name object.
 * <pre>
 * Name ::= CHOICE {
 * RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE {
 * payloadType  OBJECT IDENTIFIER,
 * value ANY }
</pre> *
 */
class X500Name : ASN1Object, ASN1Choice {
    private val rdns: Array<ASN1Encodable>
    private val rdnSeq: DERSequence

    constructor(dirName: String) {
        this.rdns = BCStyle.instance.fromString(dirName)
        this.rdnSeq = DERSequence(this.rdns)
    }

    internal constructor(vals: Array<ASN1Encodable>) {
        this.rdns = vals.clone()
        this.rdnSeq = DERSequence(this.rdns)
    }

    fun rDNs(): Array<ASN1Encodable> {
        /**
         * return an array of RDNs in structure order.
         *
         * @return an array of RDN objects.
         */
        return rdns.clone()
    }

    override fun toASN1Primitive(): ASN1Primitive {
        return rdnSeq
    }


    companion object {

        fun getInstance(obj: Any?): X500Name? {
            if (obj is X500Name) {
                return obj
            }
            return null
        }
    }
}
