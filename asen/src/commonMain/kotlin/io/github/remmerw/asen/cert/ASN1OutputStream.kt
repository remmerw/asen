package io.github.remmerw.asen.cert

import kotlinx.io.Sink

/**
 * Stream that produces output based on the default encoding for the passed in objects.
 */
open class ASN1OutputStream internal constructor(private val os: Sink) {
    fun dERSubStream(): DEROutputStream {
        return DEROutputStream(os)
    }

    fun dLSubStream(): DLOutputStream {
        return DLOutputStream(os)
    }

    fun writeDL(value: Int) {
        var length = value
        if (length < 128) {
            write(length)
        } else {
            val stack = ByteArray(5)
            var pos = stack.size

            do {
                stack[--pos] = length.toByte()
                length = length ushr 8
            } while (length != 0)

            val count = stack.size - pos
            stack[--pos] = (0x80 or count).toByte()

            write(stack, pos, count + 1)
        }
    }

    fun write(b: Int) {
        os.writeByte(b.toByte())
    }

    fun write(bytes: ByteArray, off: Int, len: Int) {
        os.write(bytes, off, off + len)
    }

    fun writeEncodingDL(withID: Boolean, contents: Byte) {
        writeIdentifier(withID, BERTags.BOOLEAN)
        writeDL(1)
        write(contents.toInt())
    }


    fun writeEncodingDL(withID: Boolean, identifier: Int, contents: ByteArray) {
        writeIdentifier(withID, identifier)
        writeDL(contents.size)
        write(contents, 0, contents.size)
    }


    fun writeEncodingDL(
        withID: Boolean,
        identifier: Int,
        contents: ByteArray,
        contentsOff: Int,
        contentsLen: Int
    ) {
        writeIdentifier(withID, identifier)
        writeDL(contentsLen)
        write(contents, contentsOff, contentsLen)
    }


    fun writeEncodingDL(
        withID: Boolean, contents: ByteArray, contentsLen: Int,
        contentsSuffix: Byte
    ) {
        writeIdentifier(withID, BERTags.BIT_STRING)
        writeDL(contentsLen + 1)
        write(contents, 0, contentsLen)
        write(contentsSuffix.toInt())
    }


    fun writeIdentifier(withID: Boolean, identifier: Int) {
        if (withID) {
            write(identifier)
        }
    }


    fun writeIdentifier(flags: Int, value: Int) {
        var tag = value
        if (tag < 31) {
            write(flags or tag)
        } else {
            val stack = ByteArray(6)
            var pos = stack.size

            stack[--pos] = (tag and 0x7F).toByte()
            while (tag > 127) {
                tag = tag ushr 7
                stack[--pos] = (tag and 0x7F or 0x80).toByte()
            }

            stack[--pos] = (flags or 0x1F).toByte()

            write(stack, pos, stack.size - pos)
        }
    }

    open fun writePrimitive(primitive: ASN1Primitive) {
        primitive.encode(this, true)
    }

    open fun writeBitPrimitives(primitives: Array<ASN1BitString>) {
        for (primitive in primitives) {
            primitive.encode(this, true)
        }
    }

    open fun writeOctetPrimitives(primitives: Array<ASN1OctetString>) {
        for (primitive in primitives) {
            primitive.encode(this, true)
        }
    }
}
