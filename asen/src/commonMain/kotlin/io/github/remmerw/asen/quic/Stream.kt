package io.github.remmerw.asen.quic

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.debug
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.math.min

class Stream(
    internal val connection: Connection, private val streamId: Int,
    streamHandlerFunction: (Stream) -> StreamHandler
) {
    private val streamFlowControl = StreamFlowControl(
        connection,
        connection.determineInitialMaxStreamData(this)
    )
    private val receiverMaxDataIncrement: Long


    @Volatile
    private var marked: PeerId? = null

    // not required to be thread safe, only invoked from the receiver thread
    private val frames: MutableList<FrameReceived.StreamFrame> = mutableListOf() // no concurrency
    private val response: MutableList<ByteArray> = arrayListOf()

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in
    // the queue determines the next byte(s) to send.
    private val sendQueue: Buffer = Buffer()
    private val mutex = Mutex()

    // Reset indicates whether the OutputStream has been reset.
    @OptIn(ExperimentalAtomicApi::class)
    private val reset = AtomicBoolean(false)

    @OptIn(ExperimentalAtomicApi::class)
    private val terminate = AtomicBoolean(false)

    private val streamHandler: StreamHandler
    private val sendRequestQueue = connection.sendRequestQueue(Level.App)
    private val requestFinish = Semaphore(1, 1)

    // meaning that no more bytes can be written by caller.
    @Volatile
    private var isFinal = false

    // Current offset is the offset of the next byte in the stream that will be sent.
    // Thread safety: only used by sender thread, no concurrency
    private var currentOffset: Long = 0 // no concurrency

    @Volatile
    private var resetErrorCode = 0L

    @Volatile
    private var allDataReceived = false
    private var receiverFlowControlLimit =
        connection.initialMaxStreamDataBidiRemote // no concurrency
    private var lastCommunicatedMaxData: Long // no concurrency
    private var processedToOffset: Long = 0 // no concurrency

    // Stream offset at which the stream was last blocked, for detecting the first time stream is blocked at a certain offset.
    private var blockedOffset: Long = 0 // no concurrency


    init {
        this.lastCommunicatedMaxData = receiverFlowControlLimit
        this.receiverMaxDataIncrement = (receiverFlowControlLimit *
                Settings.RECEIVER_MAX_DATA_INCREMENT_FACTOR).toLong()
        this.streamHandler = streamHandlerFunction.invoke(this)
    }

    internal suspend fun add(frame: FrameReceived.StreamFrame) {
        val added = addFrame(frame)
        if (added) {
            broadcast() // this blocks the parsing of further packets
        }
    }

    suspend fun increaseMaxStreamDataAllowed(maxStreamData: Long) {
        val streamWasBlocked = streamFlowControl.increaseMaxStreamDataAllowed(maxStreamData)
        if (streamWasBlocked) {
            unblock()
        }
    }

    private suspend fun broadcast() {
        var bytesRead = 0


        val removes: MutableList<FrameReceived.StreamFrame> = mutableListOf()

        val iterator = frames.sorted().iterator()
        var isFinal = false
        while (iterator.hasNext()) {
            val frame = iterator.next()

            if (frame.offset <= processedToOffset) {
                val upToOffset = frame.offsetLength()
                if (upToOffset >= processedToOffset) {
                    bytesRead += frame.length

                    if (streamHandler.readFully()) {
                        val data = frame.streamData
                        response.add(data)
                    } else {
                        val data = frame.streamData
                        val buffer = Buffer()
                        buffer.write(data)
                        streamHandler.data(buffer)
                    }

                    processedToOffset = frame.offsetLength()

                    if (frame.isFinal) {
                        isFinal = true
                    }

                    removes.add(frame)
                }
            } else {
                break
            }
        }
        frames.removeAll(removes)

        if (bytesRead > 0) {
            updateAllowedFlowControl(bytesRead)
        }


        if (frames.isEmpty()) {
            allDataReceived = isFinal
            if (allDataReceived) {
                if (streamHandler.readFully()) {
                    requestFinish.release()
                } else {
                    streamHandler.fin()
                }
            }
        }
    }

    private suspend fun updateAllowedFlowControl(bytesRead: Int) {
        // Slide flow control window forward (with as much bytes as are read)
        receiverFlowControlLimit += bytesRead.toLong()
        connection.updateConnectionFlowControl(bytesRead)
        // Avoid sending flow control updates with every single read; check diff with last
        // send max data
        if (receiverFlowControlLimit - lastCommunicatedMaxData > receiverMaxDataIncrement) {
            sendRequestQueue.appendRequest(
                createMaxStreamDataFrame(streamId, receiverFlowControlLimit)
            )
            lastCommunicatedMaxData = receiverFlowControlLimit
        }
    }


    val isUnidirectional: Boolean
        get() =// https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
        // "The second least significant bit (0x2) of the stream ID distinguishes
        //   between bidirectional streams (with the bit set to 0) and
            //   unidirectional streams (with the bit set to 1)."
            (streamId and 0x0002) == 0x0002

    val isClientInitiatedBidirectional: Boolean
        get() =// "Client-initiated streams have even-numbered stream IDs (with the bit set to 0)"
            (streamId and 0x0003) == 0x0000

    val isServerInitiatedBidirectional: Boolean
        get() =// "server-initiated streams have odd-numbered stream IDs"
            (streamId and 0x0003) == 0x0001


    @OptIn(ExperimentalAtomicApi::class)
    suspend fun resetStream(errorCode: Long) {
        if (!reset.exchange(true)) {
            resetErrorCode = errorCode
            sendRequestQueue.appendRequest(createResetFrame())
        }
        terminate(errorCode)
    }

    suspend fun close() {
        terminate()
    }

    /**
     * Terminates the receiving input stream (abruptly). Is called when peer sends a RESET_STREAM frame
     *
     *
     * This method is intentionally package-protected, as it should only be called by the StreamManager class.
     */
    suspend fun terminate(errorCode: Long) {
        if (errorCode > 0) {
            debug("Terminate (reset) Stream $streamId Error code $errorCode")
        }

        terminate()
    }


    @Suppress("unused")
    suspend fun stopLoading(errorCode: Int) {
        // Note that QUIC specification does not define application protocol error codes.
        // By absence of an application specified error code, the arbitrary code 0 is used.
        if (!allDataReceived) {
            sendRequestQueue.appendRequest(createStopSendingFrame(streamId, errorCode.toLong()))
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    suspend fun terminate() {
        reset.compareAndSet(expectedValue = false, newValue = true)
        sendQueue.clear()
        streamFlowControl.unregister()
        response.clear()

        try {
            requestFinish.release()
        } catch (_: Throwable) {
        }

        connection.unregisterStream(streamId)

        if (!terminate.exchange(true)) {
            streamHandler.terminated()
        }
    }


    suspend fun writeOutput(isFinal: Boolean, buffer: Buffer) {
        this.isFinal = isFinal

        mutex.withLock {
            sendQueue.write(buffer, buffer.size)
        }

        sendRequestQueue.appendRequest(object : FrameSupplier {
            override suspend fun nextFrame(maxSize: Int): Frame? {
                return sendFrame(maxSize)
            }
        }, Settings.MIN_FRAME_SIZE)
    }


    // this is a blocking request with the given timeout [fin is written, no more writing data allowed]
    suspend fun request(timeout: Long, data: Buffer): Buffer {
        writeOutput(true, data)

        try {
            return withTimeout(timeout * 1000L) {
                requestFinish.acquire()
                if (!allDataReceived) {
                    connection.close()
                    Buffer()
                } else {
                    response()
                }
            }
        } catch (_: Throwable) {
            connection.close()
            return Buffer()
        }
    }

    private fun response(): Buffer {

        val buffer = Buffer()
        for (entry in response) {
            buffer.write(entry)
        }
        response.clear()
        return buffer
    }


    fun mark(peerId: PeerId) {
        marked = peerId
    }

    fun marked(): PeerId? {
        return marked
    }

    fun isMarked(): Boolean {
        return marked != null
    }


    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun sendFrame(maxFrameSize: Int): Frame? {
        if (reset.load()) {
            return null
        }
        mutex.withLock {
            if (!sendQueue.exhausted()) {
                val flowControlLimit: Long = streamFlowControl.flowControlLimit

                if (flowControlLimit < 0) {
                    return null
                }

                var maxBytesToSend = sendQueue.size.toInt()

                if (flowControlLimit > currentOffset || maxBytesToSend == 0) {
                    val dummyFrameLength = frameLength(streamId, currentOffset, 0)

                    maxBytesToSend = min(
                        maxBytesToSend,
                        maxFrameSize - dummyFrameLength - 1
                    ) // Take one byte extra for length field var int
                    val maxAllowedByFlowControl = (streamFlowControl.increaseFlowControlLimit(
                        currentOffset + maxBytesToSend
                    ) - currentOffset).toInt()
                    if (maxAllowedByFlowControl < 0) {
                        return null
                    }
                    maxBytesToSend = min(maxAllowedByFlowControl, maxBytesToSend)

                    val dataToSend = sendQueue.readByteArray(maxBytesToSend)
                    var finalFrame = false

                    if (sendQueue.exhausted()) {
                        finalFrame = this.isFinal
                    }

                    val streamFrame = createStreamFrame(
                        streamId, currentOffset, dataToSend, finalFrame
                    )

                    currentOffset += maxBytesToSend


                    if (!sendQueue.exhausted()) {
                        sendRequestQueue.appendRequest(object : FrameSupplier {
                            override suspend fun nextFrame(maxSize: Int): Frame? {
                                return sendFrame(maxSize)
                            }
                        }, Settings.MIN_FRAME_SIZE)
                    }

                    if (finalFrame) {
                        // Done! Retransmissions may follow, but don't need flow control.
                        streamFlowControl.unregister()
                    }

                    return streamFrame
                } else {
                    // So flowControlLimit <= currentOffset
                    // Check if this condition hasn't been handled before
                    if (currentOffset != blockedOffset) {
                        // Not handled before, remember this offset, so this isn't executed twice for the same offset
                        blockedOffset = currentOffset
                        // And let peer know
                        // https://www.rfc-editor.org/rfc/rfc9000.html#name-data-flow-control
                        // "A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
                        //  that it has data to write but is blocked by flow control limits."
                        val frame = sendBlockReason()
                        if (frame != null) {
                            sendRequestQueue.appendRequest(frame)
                        }
                    }
                }
            }
        }
        return null
    }

    suspend fun unblock() {
        // Stream might have been blocked (or it might have filled the flow control window exactly),
        // queue send request and let sendFrame method determine whether there is more to send or not.
        sendRequestQueue.appendRequest(object : FrameSupplier {
            override suspend fun nextFrame(maxSize: Int): Frame? {
                return sendFrame(maxSize)
            }
        }, Settings.MIN_FRAME_SIZE)
        // No need to flush, as this is called while processing received message
    }

    /**
     * Sends StreamDataBlockedFrame or DataBlockedFrame to the peer, provided the blocked condition is still true.
     */
    private fun sendBlockReason(): Frame? {
        // Retrieve actual block reason; could be "none" when an update has been received in the meantime.
        val blockReason: BlockReason = streamFlowControl.flowControlBlockReason
        return when (blockReason) {
            BlockReason.STREAM_DATA_BLOCKED -> createStreamDataBlockedFrame(
                streamId, currentOffset
            )

            BlockReason.DATA_BLOCKED -> createDataBlockedFrame(streamFlowControl.maxDataAllowed())
            else -> null
        }
    }

    private fun createResetFrame(): Frame {
        return createResetStreamFrame(streamId, resetErrorCode, currentOffset)
    }

    /**
     * Add a stream frame to this stream. The frame can contain any number of bytes positioned anywhere in the stream;
     * the read method will take care of returning stream bytes in the right order, without gaps.
     *
     * @return true if the frame is adds bytes to this stream; false if the frame does not add bytes to the stream
     * (because the frame is a duplicate or its stream bytes where already received with previous frames).
     */
    private fun addFrame(frame: FrameReceived.StreamFrame): Boolean {
        if (frame.offset >= processedToOffset) {
            return frames.add(frame)
        } else {
            debug("Frame not added $frame")
            return false
        }
    }


    private class StreamFlowControl(
        private val connection: Connection, // The maximum amount of data that a stream would be allowed to send (to the peer), ignoring possible connection limit
        @field:Volatile private var maxStreamDataAllowed: Long
    ) {
        // The maximum amount of data that is already assigned to a stream (i.e. already sent, or upon being sent)
        @Volatile
        private var maxStreamDataAssigned = 0L

        fun increaseMaxStreamDataAllowed(maxStreamData: Long): Boolean {
            var streamWasBlocked = false
            if (maxStreamDataAllowed != Settings.UNREGISTER) {
                // If frames are received out of order, the new max can be smaller than the current value.
                if (maxStreamData > maxStreamDataAllowed) {
                    if (maxStreamDataAssigned != Settings.UNREGISTER) {
                        streamWasBlocked = maxStreamDataAssigned == maxStreamDataAllowed
                                && connection.maxDataAssigned() != connection.maxDataAllowed()
                        maxStreamDataAllowed = maxStreamData
                    }
                }
            }
            return streamWasBlocked
        }


        val flowControlLimit: Long
            /**
             * Returns the maximum flow control limit for the given stream, if it was requested now. Note that this limit
             * cannot be used to send data on the stream, as the flow control credits are not yet reserved.
             */
            get() {
                val currentMasStreamDataAssigned = maxStreamDataAssigned
                val currentMaxStreamDataAllowed = maxStreamDataAllowed
                if (currentMasStreamDataAssigned != Settings.UNREGISTER &&
                    currentMaxStreamDataAllowed != Settings.UNREGISTER
                ) {
                    return currentMasStreamDataAssigned + currentStreamCredits(
                        currentMasStreamDataAssigned, currentMaxStreamDataAllowed
                    )
                }
                return Settings.UNREGISTER
            }


        /**
         * Returns the maximum possible flow control limit for the given stream, taking into account both stream and connection
         * flow control limits. Note that the returned limit is not yet reserved for use by this stream!
         */
        fun currentStreamCredits(maxStreamDataAssigned: Long, maxStreamDataAllowed: Long): Long {
            var maxStreamIncrement = maxStreamDataAllowed - maxStreamDataAssigned
            val maxPossibleDataIncrement =
                connection.maxDataAllowed() - connection.maxDataAssigned()
            if (maxStreamIncrement > maxPossibleDataIncrement) {
                maxStreamIncrement = maxPossibleDataIncrement
            }
            return maxStreamIncrement
        }

        /**
         * Request to increase the flow control limit for the indicated stream to the indicated value. Whether this is
         * possible depends on whether the stream flow control limit allows this and whether the connection flow control
         * limit has enough "unused" credits.
         *
         * @return the new flow control limit for the stream: the offset of the last byte sent on the stream may not past this limit.
         */
        fun increaseFlowControlLimit(requestedLimit: Long): Long {
            val currentMasStreamDataAssigned = maxStreamDataAssigned
            val currentMaxStreamDataAllowed = maxStreamDataAllowed

            if (currentMasStreamDataAssigned != Settings.UNREGISTER &&
                currentMaxStreamDataAllowed != Settings.UNREGISTER
            ) {
                val possibleStreamIncrement = currentStreamCredits(
                    currentMasStreamDataAssigned, currentMaxStreamDataAllowed
                )
                val requestedIncrement = requestedLimit - currentMasStreamDataAssigned
                val proposedStreamIncrement =
                    min(requestedIncrement, possibleStreamIncrement)

                require(requestedIncrement >= 0)

                connection.addMaxDataAssigned(proposedStreamIncrement)
                maxStreamDataAssigned = currentMasStreamDataAssigned + proposedStreamIncrement

                return maxStreamDataAssigned
            }
            return Settings.UNREGISTER
        }

        fun unregister() {
            maxStreamDataAllowed = Settings.UNREGISTER
            maxStreamDataAssigned = Settings.UNREGISTER
        }

        /**
         * Returns the current connection flow control limit (maxDataAllowed).
         *
         * @return current connection flow control limit (maxDataAllowed)
         */
        fun maxDataAllowed(): Long {
            return connection.maxDataAllowed()
        }


        val flowControlBlockReason: BlockReason
            /**
             * Returns the reason why a given stream is blocked, which can be due that the stream flow control limit is reached
             * or the connection data limit is reached.
             */
            get() {
                if (maxStreamDataAssigned == maxStreamDataAllowed) {
                    return BlockReason.STREAM_DATA_BLOCKED
                }
                if (connection.maxDataAllowed() == connection.maxDataAssigned()) {
                    return BlockReason.DATA_BLOCKED
                }

                return BlockReason.NOT_BLOCKED
            }

    }


}
