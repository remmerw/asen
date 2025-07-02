package io.github.remmerw.asen.cert

/**
 * This interface provides a profile to conform to when
 * DNs are being converted into strings and back. The idea being that we'll be able to deal with
 * the number of standard ways the fields in a DN should be
 * encoded into their ASN.1 counterparts - a number that is rapidly approaching the
 * number of machines on the internet.
 */
interface X500NameStyle {
    /**
     * Convert the passed in String value into the appropriate ASN.1
     * encoded object.
     *
     * @param oid   the OID associated with the value in the DN.
     * @param value the value of the particular DN component.
     * @return the ASN.1 equivalent for the value.
     */
    fun stringToValue(oid: ASN1ObjectIdentifier, value: String): ASN1Encodable

    /**
     * Return the OID associated with the passed in name.
     *
     * @param attrName the string to match.
     * @return an OID
     */
    fun attrNameToOID(attrName: String): ASN1ObjectIdentifier
}