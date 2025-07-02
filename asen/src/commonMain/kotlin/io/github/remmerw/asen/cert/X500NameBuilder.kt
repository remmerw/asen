package io.github.remmerw.asen.cert

/**
 * A builder class for making X.500 Name objects.
 */
class X500NameBuilder(private val template: X500NameStyle) {
    private val rdns = mutableListOf<RDN>()

    /**
     * Add an RDN based on a single OID and a string representation of its value.
     *
     * @param oid   the OID for this RDN.
     * @param value the string representation of the value the OID refers to.
     * @return the current builder instance.
     */
    fun addRDN(oid: ASN1ObjectIdentifier, value: String): X500NameBuilder {
        this.addRDN(oid, template.stringToValue(oid, value))

        return this
    }

    /**
     * Add an RDN based on a single OID and an ASN.1 value.
     *
     * @param oid   the OID for this RDN.
     * @param value the ASN.1 value the OID refers to.
     * @return the current builder instance.
     */
    private fun addRDN(oid: ASN1ObjectIdentifier, value: ASN1Encodable): X500NameBuilder {
        rdns.add(RDN(oid, value))

        return this
    }

    /**
     * Build an X.500 name for the current builder state.
     *
     * @return a new X.500 name.
     */
    fun build(): X500Name {

        return X500Name(rdns.toTypedArray())
    }
}