package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * The TLS supported groups extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.7)
 */
@Suppress("ArrayInDataClass")
internal data class SupportedGroupsExtension(val namedGroups: Array<NamedGroup>) : Extension {
    override fun getBytes(): ByteArray {
        val extensionLength = 2 + namedGroups.size * 2
        val buffer = Buffer()
        buffer.writeShort(ExtensionType.SUPPORTED_GROUPS.value)
        buffer.writeShort(extensionLength.toShort()) // Extension data length (in bytes)

        buffer.writeShort((namedGroups.size * 2).toShort())
        for (namedGroup in namedGroups) {
            buffer.writeShort(namedGroup.value)
        }
        require(buffer.size.toInt() == 4 + extensionLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.SUPPORTED_GROUPS
    }


    companion object {
        fun createSupportedGroupsExtension(namedGroup: NamedGroup): SupportedGroupsExtension {
            val namedGroups = arrayOf(namedGroup)
            return SupportedGroupsExtension(namedGroups)
        }


        fun parse(buffer: Buffer, extensionLength: Int): SupportedGroupsExtension {
            val namedGroups: MutableList<NamedGroup> = arrayListOf()
            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 2 + 2
            )
            val namedGroupsLength = buffer.readShort().toInt()
            if (extensionDataLength != 2 + namedGroupsLength) {
                throw DecodeErrorException("inconsistent length")
            }
            if (namedGroupsLength % 2 != 0) {
                throw DecodeErrorException("invalid group length")
            }

            var i = 0
            while (i < namedGroupsLength) {
                val namedGroupBytes = (buffer.readShort() % 0xffff).toShort()
                val namedGroup: NamedGroup = NamedGroup.get(namedGroupBytes)
                namedGroups.add(namedGroup)
                i += 2
            }

            return SupportedGroupsExtension(namedGroups.toTypedArray())
        }
    }
}
