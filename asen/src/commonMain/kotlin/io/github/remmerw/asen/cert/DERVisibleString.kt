package io.github.remmerw.asen.cert

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 *
 *
 * Explicit character set escape sequences are not allowed.
 *
 */
internal class DERVisibleString(contents: ByteArray) : ASN1VisibleString(contents)
