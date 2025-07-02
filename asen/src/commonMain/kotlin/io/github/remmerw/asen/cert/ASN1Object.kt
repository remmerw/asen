package io.github.remmerw.asen.cert

import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray

/**
 * Base class for defining an ASN.1 object.
 */
abstract class ASN1Object : ASN1Encodable {

    open fun encodeTo(output: Sink, encoding: String) {
        toASN1Primitive().encodeTo(output, encoding)
    }


    fun encoded(): ByteArray {
        val bOut = Buffer()
        toASN1Primitive().encodeTo(bOut)
        return bOut.readByteArray()

    }

    /**
     * Return either the default for "BER" or a DER encoding if "DER" is specified.
     *
     * @param encoding name of encoding to use.
     * @return byte encoded object.
     */
    fun getEncoded(encoding: String): ByteArray {
        val bOut = Buffer()
        toASN1Primitive().encodeTo(bOut, encoding)
        return bOut.readByteArray()
    }

    /**
     * Method providing a primitive representation of this object suitable for encoding.
     *
     * @return a primitive representation of this object.
     */
    abstract override fun toASN1Primitive(): ASN1Primitive
}
