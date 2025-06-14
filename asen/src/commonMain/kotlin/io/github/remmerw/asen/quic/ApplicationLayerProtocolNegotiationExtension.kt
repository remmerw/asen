package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

@Suppress("ArrayInDataClass")
internal data class ApplicationLayerProtocolNegotiationExtension(val protocols: Array<String>) :
    Extension {
    override fun getBytes(): ByteArray {
        val protocolNamesLength = protocols.sumOf { p: String ->
            p.encodeToByteArray().size
        }
        val size = 4 + 2 + protocols.size + protocolNamesLength
        val buffer = Buffer()

        buffer.writeShort(ExtensionType.APPLICATION_LAYER_PROTOCOL.value)
        buffer.writeShort((size - 4).toShort())
        buffer.writeShort((size - 6).toShort())
        for (protocol in protocols) {
            val protocolName = protocol.encodeToByteArray()
            buffer.writeByte(protocolName.size.toByte())
            buffer.write(protocolName)
        }
        require(buffer.size.toInt() == size)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.PROTOCOL_NEGOTIATION
    }


    companion object {
        fun create(protocol: String): ApplicationLayerProtocolNegotiationExtension {
            require(protocol.trim { it <= ' ' }.isNotEmpty()) { "protocol cannot be empty" }
            val protocols = arrayOf(protocol)
            return ApplicationLayerProtocolNegotiationExtension(protocols)
        }


        fun parse(
            buffer: Buffer,
            extensionLength: Int
        ): ApplicationLayerProtocolNegotiationExtension {
            val extensionDataLength = validateExtensionHeader(
                buffer,
                extensionLength,
                3
            )

            var protocolsLength = buffer.readShort().toInt()
            if (protocolsLength != extensionDataLength - 2) {
                throw DecodeErrorException("inconsistent lengths")
            }

            val protocols: MutableList<String> = arrayListOf()
            while (protocolsLength > 0) {
                val protocolNameLength = buffer.readByte().toInt() and 0xff
                if (protocolNameLength > protocolsLength - 1) {
                    throw DecodeErrorException("incorrect length")
                }
                val protocolBytes = buffer.readByteArray(protocolNameLength)
                protocols.add(protocolBytes.decodeToString())
                protocolsLength -= (1 + protocolNameLength)
            }


            return ApplicationLayerProtocolNegotiationExtension(
                protocols.toTypedArray()
            )
        }
    }
}
