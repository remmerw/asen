package io.github.remmerw.asen.cert

import kotlinx.io.Sink

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
class DEROutputStream(os: Sink) : DLOutputStream(os) {

    override fun writePrimitive(primitive: ASN1Primitive) {
        primitive.toDERObject().encode(this, true)
    }

}
