package io.github.remmerw.asen.cert

interface Input {
    fun read(buf: ByteArray, off: Int, len: Int): Int
    fun read(): Int
}

/**
 * Internal use stream that allows reading of a limited number of bytes from a wrapped stream.
 */
internal abstract class LimitedInputStream(val inputStream: Input, val limit: Int) :
    Input
