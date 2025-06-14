package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

// https://tools.ietf.org/html/rfc8446#section-4.2.4
@Suppress("ArrayInDataClass")
internal data class CertificateAuthoritiesExtension(val authorities: Array<ByteArray>) : Extension {
    override fun getBytes(): ByteArray {
        val authoritiesLength =
            authorities.sumOf { x500principal: ByteArray -> x500principal.size }
        val extensionLength = authoritiesLength + authorities.size * 2 + 2 + 4
        val buffer = Buffer()

        buffer.writeShort(ExtensionType.CERTIFICATE_AUTHORITIES.value)
        buffer.writeShort((extensionLength - 4).toShort())
        buffer.writeShort((extensionLength - 6).toShort())
        for (authority in authorities) {
            buffer.writeShort(authority.size.toShort())
            buffer.write(authority)
        }
        require(buffer.size == extensionLength.toLong())
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.CERTIFICATE_AUTHORITIES
    }


    companion object {

        fun parse(buffer: Buffer, extensionLength: Int): CertificateAuthoritiesExtension {

            val authorities: MutableList<ByteArray> = arrayListOf()
            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 2
            )

            val authoritiesLength = buffer.readShort().toInt()
            if (extensionDataLength != authoritiesLength + 2) {
                throw DecodeErrorException("inconsistent length fields")
            }

            var remaining = authoritiesLength
            while (remaining > 0) {
                if (remaining < 2) {
                    throw DecodeErrorException("inconsistent length fields")
                }
                remaining -= 2
                val dnLength = buffer.readShort().toInt() and 0xffff
                if (dnLength > remaining) {
                    throw DecodeErrorException("inconsistent length fields")
                }
                if (dnLength <= buffer.size) {
                    val dn = buffer.readByteArray(dnLength)

                    remaining -= dnLength
                    try {
                        authorities.add(dn)
                    } catch (_: IllegalArgumentException) {
                        throw DecodeErrorException("authority not in DER format")
                    }
                } else {
                    throw DecodeErrorException("inconsistent length fields")
                }
            }

            return CertificateAuthoritiesExtension(authorities.toTypedArray())
        }
    }
}
