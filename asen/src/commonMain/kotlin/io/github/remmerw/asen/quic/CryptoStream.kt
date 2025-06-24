package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.Buffer
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.math.min

internal class CryptoStream internal constructor(
    private val version: Int, level: Level,
    private val tlsEngine: TlsEngine,
    private val sendRequestQueue: SendRequestQueue
) {
    private val tlsProtectionType =
        if (level == Level.Handshake) ProtectionKeysType.Handshake else if (level == Level.App) ProtectionKeysType.Application else ProtectionKeysType.None
    private val tlsMessageParser: TlsMessageParser
    private val sendQueue: Buffer = Buffer()
    private val mutex = Mutex()

    @OptIn(ExperimentalAtomicApi::class)
    private val dataToSendOffset = AtomicInt(0)

    @OptIn(ExperimentalAtomicApi::class)
    private val sendStreamSize = AtomicInt(0)
    private val frames: MutableList<FrameReceived.CryptoFrame> = mutableListOf() // no concurrency
    private var processedToOffset: Long = 0 // no concurrency

    init {
        this.tlsMessageParser =
            TlsMessageParser { buffer: Buffer, type: Int, length: Int, _: HandshakeType ->
                quicExtensionsParser(buffer, type, length)
            }
    }

    suspend fun add(cryptoFrame: FrameReceived.CryptoFrame) {
        if (addFrame(cryptoFrame)) {
            var msgSize = peekMsgSize()
            while (msgSize > 0) {
                val availableBytes = bytesAvailable().toLong()

                if (availableBytes >= (msgSize + 4)) {  // 4 is the msgSize + msgType encoded

                    val buffer = Buffer()
                    read(buffer, 4 + msgSize)


                    tlsMessageParser.parseAndProcessHandshakeMessage(
                        buffer, tlsEngine, tlsProtectionType
                    )

                    msgSize = peekMsgSize() // next iteration
                } else {
                    break
                }
            }
        }
    }

    private fun quicExtensionsParser(
        buffer: Buffer,
        type: Int,
        length: Int
    ): Extension? {

        return if (TransportParametersExtension.isCodepoint(type and 0xffff)) {
            try {
                TransportParametersExtension.parse(version, buffer, length, false)
            } catch (throwable: Throwable) {
                debug(throwable)
                throw DecodeErrorException(" " + throwable.message)
            }
        } else {
            null
        }

    }

    suspend fun write(message: HandshakeMessage) {
        write(message.bytes)
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun write(data: ByteArray) {
        val buffer = Buffer()
        buffer.write(data)
        mutex.withLock {
            sendQueue.write(buffer, buffer.size)
        }
        sendStreamSize.fetchAndAdd(data.size)
        sendRequestQueue.appendRequest(
            object : FrameSupplier {
                override suspend fun nextFrame(maxSize: Int): Frame? {
                    return sendFrame(maxSize)
                }
            },
            10
        ) // Caller should flush sender.
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun sendFrame(maxSize: Int): Frame? {
        mutex.withLock {
            val leftToSend = sendStreamSize.load() - dataToSendOffset.load()
            val bytesToSend = min(leftToSend, maxSize - 10)
            if (bytesToSend == 0) {
                return null
            }
            if (bytesToSend < leftToSend) {
                // Need (at least) another frame to send all data. Because current method
                // is the sender callback, flushing sender is not necessary.
                sendRequestQueue.appendRequest(object : FrameSupplier {
                    override suspend fun nextFrame(maxSize: Int): Frame? {
                        return sendFrame(maxSize)
                    }
                }, 10)

            }

            val frameData = ByteArray(bytesToSend)
            var frameDataOffset = 0
            while (frameDataOffset < bytesToSend && !sendQueue.exhausted()) {

                val bytesToCopy =
                    min(bytesToSend - frameDataOffset, sendQueue.size.toInt())
                val read =
                    sendQueue.readAtMostTo(
                        frameData,
                        frameDataOffset,
                        frameDataOffset + bytesToCopy
                    )
                require(read == bytesToCopy) { "Not all data are read" }

                frameDataOffset += bytesToCopy

            }

            val frame = createCryptoFrame(dataToSendOffset.load().toLong(), frameData)
            dataToSendOffset.fetchAndAdd(bytesToSend)
            return frame
        }
    }

    /**
     * Add a stream frame to this stream. The frame can contain any number of bytes positioned anywhere in the stream;
     * the read method will take care of returning stream bytes in the right order, without gaps.
     *
     * @return true if the frame is adds bytes to this stream; false if the frame does not add bytes to the stream
     * (because the frame is a duplicate or its stream bytes where already received with previous frames).
     */
    private fun addFrame(frame: FrameReceived.CryptoFrame): Boolean {
        return if (frame.offsetLength() >= processedToOffset) {
            frames.add(frame)
        } else {
            false
        }
    }

    /**
     * Returns the number of bytes that can be read from this stream.
     */
    private fun bytesAvailable(): Int {
        if (frames.isEmpty()) {
            return 0
        } else {
            var available = 0
            var countedUpTo = processedToOffset

            for (nextFrame in frames.sorted()) {
                if (nextFrame.offset <= countedUpTo) {
                    if (nextFrame.offsetLength() > countedUpTo) {
                        available += (nextFrame.offsetLength() - countedUpTo).toInt()
                        countedUpTo = nextFrame.offsetLength()
                    }
                } else {
                    break
                }
            }
            return available
        }
    }


    private fun peekMsgSize(): Int {
        for (nextFrame in frames.sorted()) {
            if (nextFrame.offset <= processedToOffset) {
                if (nextFrame.offsetLength() >= processedToOffset + 4) {
                    // Note: + 1 (because the first byte is handshake type)
                    // Note: the length is 3, the content of the msg size
                    return encodeInteger(
                        nextFrame.payload,
                        (processedToOffset - nextFrame.offset).toInt() + 1, 3
                    )
                }
            } else {
                break
            }
        }
        return 0
    }

    private fun read(buffer: Buffer, maxSize: Int) {

        val removes: MutableList<FrameReceived.CryptoFrame> = mutableListOf()
        val iterator = frames.sorted().iterator()
        var size = maxSize

        while (iterator.hasNext() && size > 0) {
            val nextFrame = iterator.next()
            if (nextFrame.offset <= processedToOffset) {
                if (nextFrame.offsetLength() > processedToOffset) {
                    val available = nextFrame.offset - processedToOffset + nextFrame.length
                    val bytesToRead = min(size, available.toInt())
                    val offset = (processedToOffset - nextFrame.offset).toInt()
                    buffer.write(
                        nextFrame.payload,
                        offset,
                        offset + bytesToRead
                    )
                    size -= bytesToRead
                    processedToOffset += bytesToRead.toLong()
                    if (nextFrame.offsetLength() <= processedToOffset) {
                        removes.add(nextFrame)
                    }
                }
            } else {
                break
            }
        }
        frames.removeAll(removes)
    }


    fun cleanup() {
        frames.clear()
        sendQueue.clear()
    }
}
