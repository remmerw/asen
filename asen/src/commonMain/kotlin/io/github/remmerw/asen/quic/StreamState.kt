package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlin.math.min

abstract class StreamState {
    var frame: ByteArray? = null
    var frameIndex: Int = 0
    var reset: Boolean = false


    fun reset() {
        frame = null
        reset = true
    }

    protected abstract fun accept(stream: Stream, frame: ByteArray)

    fun length(): Int {
        if (frame != null) {
            return frame!!.size
        }
        return 0
    }

    companion object {
        fun isProtocol(data: ByteArray): Boolean {
            var result = false
            if (data.size > 2) {
                val first = data[0] == '/'.code.toByte()
                val second = data[data.size - 1] == '\n'.code.toByte()
                result = first && second
            }
            return result
        }

        fun unsignedVarintReader(data: Buffer): ByteArray {
            if (data.size == 0L) {
                return Settings.BYTES_EMPTY
            }
            return ByteArray(readUnsignedVariant(data))
        }


        private fun readUnsignedVariant(buffer: Buffer): Int {
            var result = 0
            var cur: Int
            var count = 0
            do {
                cur = buffer.readByte().toInt() and 0xff
                result = result or ((cur and 0x7f) shl (count * 7))
                count++
            } while (((cur and 0x80) == 0x80) && count < 5)
            check((cur and 0x80) != 0x80) { "invalid unsigned variant sequence" }
            return result
        }


        fun iteration(streamState: StreamState, stream: Stream?, bytes: Buffer) {
            if (!streamState.reset) {
                if (streamState.length() == 0) {
                    streamState.frame = unsignedVarintReader(bytes)
                    streamState.frameIndex = 0
                    if (streamState.length() < 0) {
                        streamState.frame = null
                        streamState.frameIndex = 0
                        throw Exception("invalid length of < 0 : " + streamState.length())
                    } else {
                        val read = min(streamState.length(), bytes.size.toInt())
                        repeat(read) {
                            streamState.frame!![streamState.frameIndex] = bytes.readByte()
                            streamState.frameIndex++
                        }

                        if (read == streamState.length()) {
                            val frame = checkNotNull(streamState.frame)
                            streamState.frame = null
                            streamState.accept(stream!!, frame)
                        }

                        // check for a next iteration
                        if (bytes.size > 0) {
                            iteration(streamState, stream, bytes)
                        }
                    }
                } else {
                    val frame = checkNotNull(streamState.frame)
                    var remaining = streamState.frame!!.size - streamState.frameIndex
                    val read = min(remaining, bytes.size.toInt())
                    repeat(read) {
                        streamState.frame!![streamState.frameIndex] = bytes.readByte()
                        streamState.frameIndex++
                    }
                    remaining = streamState.frame!!.size - streamState.frameIndex
                    if (remaining == 0) { // frame is full
                        streamState.frame = null
                        streamState.frameIndex++
                        streamState.accept(stream!!, frame)
                    }
                    // check for a next iteration
                    if (bytes.size > 0) {
                        iteration(streamState, stream, bytes)
                    }
                }
            }
        }
    }
}
