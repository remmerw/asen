package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

@Suppress("ArrayInDataClass")
internal data class FinishedMessage(val verifyData: ByteArray, override val bytes: ByteArray) :
    HandshakeMessage {
    override val type: HandshakeType
        get() = HandshakeType.FINISHED

    companion object {
        fun createFinishedMessage(hmac: ByteArray): FinishedMessage {
            val buffer = Buffer()
            buffer.writeInt((HandshakeType.FINISHED.value.toInt() shl 24) or hmac.size)
            buffer.write(hmac)
            require(buffer.size.toInt() == 4 + hmac.size)
            return FinishedMessage(hmac, buffer.readByteArray())
        }

        fun parse(buffer: Buffer, data: ByteArray): FinishedMessage {

            val remainingLength = parseHandshakeHeader(
                buffer,
                4 + 32
            )
            val verifyData = buffer.readByteArray(remainingLength)


            return FinishedMessage(verifyData, data)
        }
    }

}
