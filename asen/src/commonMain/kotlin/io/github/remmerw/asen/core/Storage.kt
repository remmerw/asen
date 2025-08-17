package io.github.remmerw.asen.core

import io.github.remmerw.asen.debug
import kotlinx.io.Buffer
import kotlinx.io.RawSink
import kotlinx.io.RawSource
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.readByteArray
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.concurrent.withLock
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


internal const val MAX_SIZE: Int = 65536

internal const val MAX_CHARS_SIZE = 4096
private const val SPLITTER_SIZE = Short.MAX_VALUE

fun splitterSize(): Int {
    return SPLITTER_SIZE.toInt()
}

interface Node {
    val cid: Long
    val size: Long
    val name: String
    val mimeType: String
}

internal data class Fid(
    override val cid: Long,
    override val size: Long,
    override val name: String,
    override val mimeType: String,
    val links: Int
) : Node {
    init {
        require(size >= 0) { "Invalid size" }
        require(name.length <= MAX_CHARS_SIZE) { "Invalid name length" }
    }
}


internal data class Raw(
    override val cid: Long,
    override val size: Long,
    override val name: String,
    override val mimeType: String,
    val data: ByteArray,
) : Node {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Raw

        if (cid != other.cid) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cid.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}


@OptIn(ExperimentalAtomicApi::class)
data class Storage(private val directory: Path) {
    private val lock = ReentrantLock()

    @OptIn(ExperimentalAtomicApi::class)
    private val cid = AtomicLong(0L)


    init {
        var maxCid = 0L
        val files = SystemFileSystem.list(directory())
        for (file in files) {
            try {
                val res = file.name.hexToLong()
                if (res > maxCid) {
                    maxCid = res
                }
            } catch (throwable: Throwable) {
                debug(throwable)
            }
        }
        cid.store(maxCid)
    }

    internal fun currentCid(): Long {
        return cid.load()
    }

    fun directory(): Path {
        return directory
    }

    fun reset() {
        cleanupDirectory(directory)
        cid.store(0L)
    }

    fun delete() {
        reset()
        SystemFileSystem.delete(directory, false)
    }

    fun hasBlock(cid: Long): Boolean {
        return SystemFileSystem.exists(path(cid))
    }


    fun transferBlock(sink: RawSink, cid: Long): Int {
        val file = path(cid)
        require(SystemFileSystem.exists(file)) { "Block does not exists" }

        SystemFileSystem.source(file).buffered().use { source ->
            return source.transferTo(sink).toInt()
        }
    }

    fun storeBlock(cid: Long, buffer: Buffer) {
        require(buffer.size <= MAX_SIZE) { "Exceeds limit of data length" }
        val file = path(cid)
        SystemFileSystem.sink(file, false).use { sink ->
            sink.write(buffer, buffer.size)
        }
    }


    @OptIn(ExperimentalStdlibApi::class)
    private fun path(cid: Long): Path {
        return Path(directory, cid.toHexString())
    }

    fun deleteBlock(cid: Long) {
        val file = path(cid)
        SystemFileSystem.delete(file, false)
    }


    fun info(cid: Long): Node {
        val sink = Buffer()
        transferBlock(sink, cid)
        return decodeNode(cid, sink)
    }

    // Note: remove the cid block (add all links blocks recursively)
    fun delete(node: Node) {
        removeNode(this, node)
    }

    fun storeData(data: ByteArray): Node {
        require(data.size <= MAX_SIZE) { "Exceeds limit of data length" }
        lock.withLock {
            return createRaw(this, cid.incrementAndFetch(), data)
        }
    }

    fun storeText(data: String): Node {
        return storeData(data.encodeToByteArray())
    }

    fun storeFile(path: Path, mimeType: String): Node {
        require(SystemFileSystem.exists(path)) { "Path does not exists" }
        val metadata = SystemFileSystem.metadataOrNull(path)
        checkNotNull(metadata) { "Path has no metadata" }
        require(metadata.isRegularFile) { "Path is not a regular file" }
        require(mimeType.isNotBlank()) { "MimeType is blank" }
        SystemFileSystem.source(path).use { source ->
            return storeSource(source, path.name, mimeType)
        }
    }

    fun storeSource(source: RawSource, name: String, mimeType: String): Node {
        lock.withLock {
            require(name.isNotBlank()) { "Name is blank" }
            require(mimeType.isNotBlank()) { "MimeType is blank" }
            return storeSource(this, source, name, mimeType) {
                cid.incrementAndFetch()
            }
        }
    }

    fun transferTo(node: Node, path: Path) {
        SystemFileSystem.sink(path, false).use { sink ->

            if (node is Raw) {
                val buffer = Buffer()
                buffer.write(node.data)
                val totalRead: Long = node.size
                sink.write(buffer, totalRead)

            } else {
                node as Fid
                val links = node.links

                repeat(links) { i ->
                    val link = i + 1 + node.cid
                    transferBlock(sink, link)
                }
            }
        }
    }

    internal fun readByteArray(node: Node): ByteArray {
        if (node is Raw) {
            return node.data
        } else {
            node as Fid
            val links = node.links
            val sink = Buffer()
            repeat(links) { i ->
                val link = i + 1 + node.cid
                transferBlock(sink, link)
            }

            return sink.readByteArray()
        }
    }


    fun fetchData(node: Node): ByteArray {
        return readByteArray(node)
    }

    fun fetchText(node: Node): String {
        return fetchData(node).decodeToString()
    }
}

fun cleanupDirectory(dir: Path) {
    if (SystemFileSystem.exists(dir)) {
        val files = SystemFileSystem.list(dir)
        for (file in files) {
            SystemFileSystem.delete(file)
        }
    }
}

fun newStorage(): Storage {
    return newStorage(tempDirectory())
}

@OptIn(ExperimentalUuidApi::class)
private fun tempDirectory(): Path {
    val path = Path(SystemTemporaryDirectory, Uuid.random().toHexString())
    SystemFileSystem.createDirectories(path)
    return path
}

@OptIn(ExperimentalUuidApi::class)
internal fun tempFile(name: String = Uuid.random().toHexString()): Path {
    return Path(SystemTemporaryDirectory, name)
}


fun newStorage(directory: Path): Storage {
    SystemFileSystem.createDirectories(directory)
    require(
        SystemFileSystem.metadataOrNull(directory)?.isDirectory == true
    ) {
        "Path is not a directory."
    }
    return Storage(directory)
}