package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * TLS Pre-Shared Key Extension, ClientHello variant.
 * see [...](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
 */
@Suppress("ArrayInDataClass")
internal data class ClientHelloPreSharedKeyExtension(
    val identities: Array<PskIdentity>,
    val binders: Array<PskBinderEntry>,
    val binderPosition: Int
) : PreSharedKeyExtension {
    override fun getBytes(): ByteArray {
        throw IllegalArgumentException()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.CLIENT_HELLO_PRE_SHARED_KEY
    }


    data class PskIdentity(val identity: ByteArray, val obfuscatedTicketAge: Long)

    data class PskBinderEntry(val hmac: ByteArray)

    companion object {
        private const val MINIMUM_EXTENSION_DATA_SIZE = 2 + 2 + 1 + 4 + 2 + 1 + 32


        fun parse(buffer: Buffer, extensionLength: Int): ClientHelloPreSharedKeyExtension {

            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, MINIMUM_EXTENSION_DATA_SIZE
            )

            val identities: MutableList<PskIdentity> = arrayListOf()
            var remainingIdentitiesLength = buffer.readShort().toInt() and 0xffff
            var remaining = extensionDataLength - 2
            while (remainingIdentitiesLength > 0) {
                if (remaining < 2) {
                    throw DecodeErrorException("Incomplete psk identity")
                }
                val identityLength = buffer.readShort().toInt() and 0xffff
                remaining -= 2
                if (identityLength > remaining) {
                    throw DecodeErrorException("Incorrect identity length value")
                }
                val identity = buffer.readByteArray(identityLength)

                remaining -= identityLength
                if (remaining < 4) {
                    throw DecodeErrorException("Incomplete psk identity")
                }
                val obfuscatedTicketAge = buffer.readInt()
                remaining -= 4
                identities.add(PskIdentity(identity, obfuscatedTicketAge.toLong()))
                remainingIdentitiesLength -= (2 + identityLength + 4)
            }
            if (remainingIdentitiesLength != 0) {
                throw DecodeErrorException("Incorrect identities length value")
            }

            val binderPosition = buffer.size
            val binders: MutableList<PskBinderEntry> = arrayListOf()
            if (remaining < 2) {
                throw DecodeErrorException("Incomplete binders")
            }
            var bindersLength = buffer.readShort().toInt() and 0xffff
            remaining -= 2
            while (bindersLength > 0) {
                if (remaining < 1) {
                    throw DecodeErrorException("Incorrect binder value")
                }
                val binderLength = buffer.readByte().toInt() and 0xff
                remaining -= 1
                if (binderLength > remaining) {
                    throw DecodeErrorException("Incorrect binder length value")
                }
                if (binderLength < 32) {
                    throw DecodeErrorException("Invalid binder length")
                }
                val hmac = buffer.readByteArray(binderLength)

                remaining -= binderLength
                binders.add(PskBinderEntry(hmac))
                bindersLength -= (1 + binderLength)
            }
            if (bindersLength != 0) {
                throw DecodeErrorException("Incorrect binders length value")
            }
            if (remaining > 0) {
                throw DecodeErrorException("Incorrect extension data length value")
            }
            if (identities.size != binders.size) {
                throw DecodeErrorException("Inconsistent number of identities vs binders")
            }
            if (identities.isEmpty()) {
                throw DecodeErrorException("Empty OfferedPsks")
            }

            return ClientHelloPreSharedKeyExtension(
                identities.toTypedArray(),
                binders.toTypedArray(), binderPosition.toInt()
            )
        }
    }
}
