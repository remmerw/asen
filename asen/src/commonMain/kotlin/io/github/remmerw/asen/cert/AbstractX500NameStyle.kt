package io.github.remmerw.asen.cert

/**
 * This class provides some default behavior and common implementation for a
 * X500NameStyle. It should be easily extendable to support implementing the
 * desired X500NameStyle.
 */
abstract class AbstractX500NameStyle : X500NameStyle {
    /**
     * For all string values starting with '#' is assumed, that these are
     * already valid ASN.1 objects encoded in hex.
     *
     *
     * All other string values are send to
     * [AbstractX500NameStyle.encodeStringValue].
     *
     * Subclasses should overwrite
     * [AbstractX500NameStyle.encodeStringValue]
     * to change the encoding of specific types.
     *
     * @param oid   the DN name of the value.
     * @param value the String representation of the value.
     */
    override fun stringToValue(oid: ASN1ObjectIdentifier, value: String): ASN1Encodable {
        return encodeStringValue(oid, value)
    }

    /**
     * Encoded every value into a UTF8String.
     *
     *
     * Subclasses should overwrite
     * this method to change the encoding of specific types.
     *
     *
     * @param oid   the DN oid of the value
     * @param value the String representation of the value
     * @return a the value encoded into a ASN.1 object. Never returns `null`.
     */
    open fun encodeStringValue(oid: ASN1ObjectIdentifier, value: String): ASN1Encodable {
        return DERUTF8String(value)
    }
}
