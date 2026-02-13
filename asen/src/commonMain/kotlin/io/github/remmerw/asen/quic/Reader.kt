package io.github.remmerw.asen.quic

import kotlinx.io.Buffer


internal class Reader(val data: ByteArray, val size: Int) {
    private var pos: Int = 0

    fun remaining(): Int {
        return size - pos
    }

    fun getByteArray(length: Int): ByteArray {
        val end: Int = pos + length
        val result = data.copyOfRange(pos, end)
        pos = end
        return result
    }

    fun position(): Int {
        return pos
    }

    fun skip(length: Int) {
        pos += length
    }

    fun position(pos: Int) {
        this.pos = pos
    }

    fun getByte(): Byte {
        val byte = data[pos]
        pos++
        return byte
    }

    fun getShort(): Short {
        val data = Buffer()
        repeat(Short.SIZE_BYTES) {
            data.writeByte(getByte())
        }
        return data.readShort()
    }

    fun getLong(): Long {
        val data = Buffer()
        repeat(Long.SIZE_BYTES) {
            data.writeByte(getByte())
        }
        return data.readLong()
    }

    fun getInt(): Int {
        val data = Buffer()
        repeat(Int.SIZE_BYTES) {
            data.writeByte(getByte())
        }
        return data.readInt()
    }
}


