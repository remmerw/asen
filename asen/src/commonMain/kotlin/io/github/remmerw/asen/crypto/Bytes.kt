package io.github.remmerw.asen.crypto

/**
 * Immutable Wrapper around a byte array.
 *
 *
 * Wrap a bytearray so it prevents callers from modifying its contents. It does this by making a
 * copy upon initialization, and also makes a copy if the underlying bytes are requested.
 *
 * @since 1.0.0
 */
internal class Bytes(buf: ByteArray, start: Int, len: Int) {
    // We copy the data on input and output.
    private val data = ByteArray(len)

    init {
        buf.copyInto(data, 0, start, len)
    }

    /**
     * @return a copy of the bytes wrapped by this object.
     */
    fun toByteArray(): ByteArray {
        val result = ByteArray(data.size)
        data.copyInto(result, 0, 0, data.size)
        return result
    }
}