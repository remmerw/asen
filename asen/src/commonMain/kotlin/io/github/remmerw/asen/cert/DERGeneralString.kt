package io.github.remmerw.asen.cert

/**
 * ASN.1 GENERAL-STRING data payloadType.
 *
 *
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 *
 */
internal class DERGeneralString(contents: ByteArray) : ASN1GeneralString(contents)
