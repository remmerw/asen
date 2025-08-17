package io.github.remmerw.asen.core


import kotlinx.io.Buffer
import kotlinx.io.RawSource
import kotlinx.io.Source
import kotlinx.io.buffered
import kotlinx.io.readByteArray
import kotlinx.io.writeUShort
import java.net.InetSocketAddress


const val OCTET_MIME_TYPE = "application/octet-stream"
const val UNDEFINED_NAME: String = ""
const val RAW = 0x00.toByte()
const val FID = 0x01.toByte()


internal fun InetSocketAddress.encoded(): ByteArray {
    Buffer().use { buffer ->
        buffer.writeByte(address.address.size.toByte())
        buffer.write(address.address)
        buffer.writeUShort(port.toUShort())
        return buffer.readByteArray()
    }
}


internal fun readUnsignedVariant(buffer: Source): Int {
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


internal fun storeSource(
    storage: Storage,
    source: RawSource,
    name: String,
    mimeType: String,
    nextCid: (Any) -> Long
): Fid {
    var links = 0

    val split = splitterSize().toLong()
    val chunk = Buffer()

    var size = 0L
    var done = false

    val fidCid = nextCid.invoke(Any())

    while (!done) {
        var read = 0L
        while (read < split) {
            val maxToRead = split - read
            val iterRead = source.readAtMostTo(chunk, maxToRead)
            if (iterRead <= 0) {
                done = true
                break
            }
            read += iterRead
        }

        if (read > 0) {
            val cid = nextCid.invoke(Any())
            require(chunk.size <= split) { "Invalid chunk size" }
            storage.storeBlock(cid, chunk)
            links++
            size += read
        }
        chunk.clear()
    }

    val buffer = encodeFid(links, size, name, mimeType)
    storage.storeBlock(fidCid, buffer)
    return Fid(fidCid, size, name, mimeType, links)
}

internal fun removeNode(storage: Storage, node: Node) {
    when (node) {
        is Fid -> {
            removeBlocks(storage, node)
        }

        is Raw -> {
            removeBlocks(storage, node)
        }

        else -> {
            throw IllegalStateException("not supported node")
        }
    }
}

private fun removeBlocks(storage: Storage, raw: Raw) {
    storage.deleteBlock(raw.cid)
}

private fun removeBlocks(storage: Storage, fid: Fid) {
    repeat(fid.links) { i ->
        val link = i + 1 + fid.cid
        storage.deleteBlock(link)
    }
    storage.deleteBlock(fid.cid)
}


internal fun createRaw(
    storage: Storage, cid: Long, data: ByteArray
): Raw {
    val buffer = encodeRaw(data)
    storage.storeBlock(cid, buffer)
    return Raw(
        cid = cid,
        size = data.size.toLong(),
        name = UNDEFINED_NAME,
        mimeType = OCTET_MIME_TYPE,
        data = data
    )
}


internal fun encodeRaw(data: ByteArray): Buffer {
    val buffer = Buffer()
    buffer.writeByte(RAW)
    buffer.write(data)
    return buffer
}


internal fun encodeFid(
    links: Int, size: Long, name: String, mimeType: String
): Buffer {
    require(size >= 0) { "Invalid size" }
    require(
        name.length <= MAX_CHARS_SIZE
    ) { "Max name length is $MAX_CHARS_SIZE" }
    require(
        mimeType.length <= MAX_CHARS_SIZE
    ) { "Max mime type length is $MAX_CHARS_SIZE" }

    val rawName = name.encodeToByteArray()
    val rawMimeType = mimeType.encodeToByteArray()

    val length = lengthFid(rawName, rawMimeType)

    val buffer = Buffer()
    buffer.writeByte(FID)
    buffer.writeInt(links)
    buffer.writeLong(size)

    writeUnsignedVariant(buffer, rawName.size.toLong())
    buffer.write(rawName)

    writeUnsignedVariant(buffer, rawMimeType.size.toLong())
    buffer.write(rawMimeType)

    require(buffer.size.toInt() == length)
    return buffer
}

private fun lengthFid(
    name: ByteArray, mimeType: ByteArray
): Int {
    var length = 1 +
            Int.SIZE_BYTES +  // links size
            Long.SIZE_BYTES // size


    length = (length +
            unsignedVariantSize(name.size.toLong()) // name size
            + name.size)

    length = (length +
            unsignedVariantSize(mimeType.size.toLong()) // name size
            + mimeType.size)

    return length
}

internal fun decodeNode(cid: Long, source: RawSource): Node {
    source.buffered().use { buffer ->
        val type: Byte = buffer.readByte()

        if (type == RAW) {
            val data = buffer.readByteArray()
            return Raw(
                cid = cid,
                size = data.size.toLong(),
                name = UNDEFINED_NAME,
                mimeType = OCTET_MIME_TYPE,
                data = data
            )
        } else {
            val links = buffer.readInt()
            val size = buffer.readLong()
            val nameLength = readUnsignedVariant(buffer)
            val name = buffer.readByteArray(nameLength).decodeToString()

            val mimeTypeLength = readUnsignedVariant(buffer)
            val mimeType = buffer.readByteArray(mimeTypeLength).decodeToString()


            return Fid(cid, size, name, mimeType, links)
        }
    }
}

