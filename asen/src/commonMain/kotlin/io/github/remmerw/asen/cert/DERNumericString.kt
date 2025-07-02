package io.github.remmerw.asen.cert

/**
 * DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 *
 *
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 *
 *
 * See X.680 section 37.2.
 *
 *
 * Explicit character set escape sequences are not allowed.
 */
internal class DERNumericString(contents: ByteArray) : ASN1NumericString(contents)
