package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * The TLS supported groups extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.3)
 * "Note: This enum is named "SignatureScheme" because there is already a "SignatureAlgorithm" payloadType in TLS 1.2,
 * which this replaces.  We use the term "signature algorithm" throughout the text."
 */
internal data class SignatureAlgorithmsExtension(val algorithms: List<SignatureScheme>) :
    Extension {
    override fun getBytes(): ByteArray {
        val extensionLength = 2 + algorithms.size * 2
        val buffer = Buffer()
        buffer.writeShort(ExtensionType.SIGNATURE_ALGORITHMS.value)
        buffer.writeShort(extensionLength.toShort()) // Extension data length (in bytes)

        buffer.writeShort((algorithms.size * 2).toShort())
        for (namedGroup in algorithms) {
            buffer.writeShort(namedGroup.value)
        }
        require(buffer.size.toInt() == 4 + extensionLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.SIGNATURE_ALGORITHMS
    }


    companion object {
        fun parse(buffer: Buffer, extensionLength: Int): SignatureAlgorithmsExtension {
            val algorithms: MutableList<SignatureScheme> = arrayListOf()
            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 2 + 2
            )
            val supportedAlgorithmsLength = buffer.readShort().toInt()
            if (extensionDataLength != 2 + supportedAlgorithmsLength) {
                throw DecodeErrorException("inconsistent length")
            }
            if (supportedAlgorithmsLength % 2 != 0) {
                throw DecodeErrorException("invalid group length")
            }

            var i = 0
            while (i < supportedAlgorithmsLength) {
                val supportedAlgorithmsBytes = (buffer.readShort() % 0xffff).toShort()
                val algorithm: SignatureScheme =
                    SignatureScheme.get(supportedAlgorithmsBytes)
                algorithms.add(algorithm)
                i += 2
            }

            return SignatureAlgorithmsExtension(algorithms)
        }
    }
}
