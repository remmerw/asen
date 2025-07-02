package io.github.remmerw.asen.cert

/**
 * DER BMPString object encodes BMP (*Basic Multilingual Plane*) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 *
 *
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 *
 */
internal class DERBMPString(string: CharArray) : ASN1BMPString(string)
