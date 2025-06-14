package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * TLS Pre-Shared Key Exchange Modes extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2.9)
 */
@Suppress("ArrayInDataClass")
internal data class PskKeyExchangeModesExtension(val keyExchangeModes: Array<PskKeyExchangeMode>) :
    Extension {
    override fun getBytes(): ByteArray {
        val extensionLength = (1 + keyExchangeModes.size).toShort()
        val buffer = Buffer()

        buffer.writeShort(ExtensionType.ASK_KEY_EXCHANGE_MODES.value)
        buffer.writeShort(extensionLength) // Extension payload length (in bytes)

        buffer.writeByte(keyExchangeModes.size.toByte())
        keyExchangeModes.forEach { mode: PskKeyExchangeMode -> buffer.writeByte(mode.value) }
        require(buffer.size.toInt() == 4 + extensionLength)
        return buffer.readByteArray()
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.PSK_KEY_EXCHANGE_MODES
    }


    companion object {
        fun createPskKeyExchangeModesExtension(keyExchangeMode: PskKeyExchangeMode): PskKeyExchangeModesExtension {
            val keyExchangeModes =
                arrayOf(keyExchangeMode)
            return PskKeyExchangeModesExtension(keyExchangeModes)
        }

        fun createPskKeyExchangeModesExtension(keyExchangeModes: Array<PskKeyExchangeMode>): PskKeyExchangeModesExtension {
            return PskKeyExchangeModesExtension(keyExchangeModes)
        }

        fun parse(buffer: Buffer, extensionLength: Int): PskKeyExchangeModesExtension {
            val keyExchangeModes: MutableList<PskKeyExchangeMode> = arrayListOf()
            val extensionDataLength = validateExtensionHeader(
                buffer, extensionLength, 2
            )
            val pskKeyExchangeModesLength = buffer.readByte().toInt()
            if (extensionDataLength != 1 + pskKeyExchangeModesLength) {
                throw DecodeErrorException("inconsistent length")
            }
            repeat(pskKeyExchangeModesLength) {
                val modeByte = buffer.readByte().toInt()
                when (modeByte) {
                    PskKeyExchangeMode.PSK_KE.value.toInt() -> {
                        keyExchangeModes.add(PskKeyExchangeMode.PSK_KE)
                    }

                    PskKeyExchangeMode.PSK_DHE_KE.value.toInt() -> {
                        keyExchangeModes.add(PskKeyExchangeMode.PSK_DHE_KE)
                    }

                    else -> {
                        throw DecodeErrorException("invalid psk key exchange mocde")
                    }
                }
            }

            return PskKeyExchangeModesExtension(keyExchangeModes.toTypedArray())
        }
    }
}
