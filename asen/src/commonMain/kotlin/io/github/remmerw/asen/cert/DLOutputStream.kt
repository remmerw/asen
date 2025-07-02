package io.github.remmerw.asen.cert

import kotlinx.io.Sink

/**
 * Stream that outputs encoding based on definite length.
 */
open class DLOutputStream(os: Sink) : ASN1OutputStream(os) {


    override fun writePrimitive(primitive: ASN1Primitive) {
        primitive.toDLObject().encode(this, true)
    }

}
