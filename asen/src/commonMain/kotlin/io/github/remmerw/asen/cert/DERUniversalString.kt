package io.github.remmerw.asen.cert

/**
 * DER UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
internal class DERUniversalString(contents: ByteArray) : ASN1UniversalString(contents)
