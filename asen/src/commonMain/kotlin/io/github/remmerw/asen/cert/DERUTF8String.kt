package io.github.remmerw.asen.cert

/**
 * DER UTF8String object.
 */
class DERUTF8String : ASN1UTF8String {
    /**
     * Basic constructor
     *
     * @param string the string to be carried in the UTF8String object,
     */
    constructor(string: String) : super(string)

    internal constructor(contents: ByteArray) : super(contents)
}
