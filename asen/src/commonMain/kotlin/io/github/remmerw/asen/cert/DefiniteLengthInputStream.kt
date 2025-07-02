package io.github.remmerw.asen.cert

import kotlin.math.min


/**
 * Parse data stream of expected ASN.1 data expecting definite-length encoding..
 */
internal class DefiniteLengthInputStream(inputStream: Input, length: Int, limit: Int) :
    LimitedInputStream(inputStream, limit), Input {
    private val _originalLength: Int

    var remaining: Int
        private set

    init {
        if (length <= 0) {
            require(length >= 0) { "negative lengths not allowed" }
        }

        this._originalLength = length
        this.remaining = length
    }

    override fun read(): Int {
        if (remaining == 0) {
            return -1
        }

        val b = this@DefiniteLengthInputStream.inputStream.read()

        if (b < 0) {
            throw Exception("DEF length $_originalLength object truncated by $remaining")
        }

        --remaining

        return b
    }


    override fun read(buf: ByteArray, off: Int, len: Int): Int {
        if (remaining == 0) {
            return -1
        }

        val toRead = min(len, remaining)
        val numRead = this@DefiniteLengthInputStream.inputStream.read(buf, off, toRead)

        if (numRead < 0) {
            throw Exception("DEF length $_originalLength object truncated by $remaining")
        }

        remaining -= numRead

        return numRead
    }


    fun readAllIntoByteArray(buf: ByteArray) {
        require(remaining == buf.size) { "buffer length not right for data" }

        if (remaining == 0) {
            return
        }

        // make sure it's safe to do this!
        val limit = limit
        if (remaining >= limit) {
            throw Exception("corrupted stream - out of bounds length found: $remaining >= $limit")
        }

        if ((readFully(
                this@DefiniteLengthInputStream.inputStream,
                buf,
                0,
                buf.size
            ).let { remaining -= it; remaining }) != 0
        ) {
            throw Exception("DEF length $_originalLength object truncated by $remaining")
        }
    }

    fun toByteArray(): ByteArray {
        if (remaining == 0) {
            return ZERO_BYTES
        }

        // make sure it's safe to do this!
        val limit = limit
        if (remaining >= limit) {
            throw Exception("corrupted stream - out of bounds length found: $remaining >= $limit")
        }

        val bytes = ByteArray(remaining)
        if ((readFully(
                this@DefiniteLengthInputStream.inputStream,
                bytes,
                0,
                bytes.size
            ).let { remaining -= it; remaining }) != 0
        ) {
            throw Exception("DEF length $_originalLength object truncated by $remaining")
        }

        return bytes
    }

}
