package io.github.remmerw.asen.cert

/**
 * DER IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
class DERIA5String : ASN1IA5String {
    /**
     * Basic constructor - without validation.
     *
     * @param string the base string to use..
     */
    constructor(string: String) : super(string)


    internal constructor(contents: ByteArray) : super(contents)
}
