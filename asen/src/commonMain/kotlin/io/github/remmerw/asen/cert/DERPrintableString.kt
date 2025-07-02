package io.github.remmerw.asen.cert

/**
 * DER PrintableString object.
 *
 *
 * X.680 section 37.4 defines PrintableString character codes as ASCII subset of following characters:
 *
 *
 *  * Latin capital letters: 'A' .. 'Z'
 *  * Latin small letters: 'a' .. 'z'
 *  * Digits: '0'..'9'
 *  * Space
 *  * Apostrophe: '\''
 *  * Left parenthesis: '('
 *  * Right parenthesis: ')'
 *  * Plus sign: '+'
 *  * Comma: ','
 *  * Hyphen-minus: '-'
 *  * Full stop: '.'
 *  * Solidus: '/'
 *  * Colon: ':'
 *  * Equals sign: '='
 *  * Question mark: '?'
 *
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
class DERPrintableString : ASN1PrintableString {
    constructor(string: String) : super(string)

    internal constructor(contents: ByteArray) : super(contents)
}
