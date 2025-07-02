package io.github.remmerw.asen.cert

/**
 * DER T61String (also the teletex string), try not to use this if you don't need to.
 * The standard support the encoding for this has been withdrawn.
 */
internal class DERT61String(contents: ByteArray) : ASN1T61String(contents)
