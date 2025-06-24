package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.fetchAndIncrement

open class ConnectionStreams(version: Int) :
    ConnectionFlow(version) {
    private val streams: MutableMap<Int, Stream> = mutableMapOf()
    private val mutex = Mutex()

    @OptIn(ExperimentalAtomicApi::class)
    private val maxOpenStreamIdUni = AtomicLong(Settings.MAX_STREAMS_UNI.toLong())

    @OptIn(ExperimentalAtomicApi::class)
    private val maxOpenStreamIdBidi = AtomicLong(Settings.MAX_STREAMS_BIDI.toLong())

    @OptIn(ExperimentalAtomicApi::class)
    private val maxOpenStreamsUniUpdateQueued = AtomicBoolean(false)

    @OptIn(ExperimentalAtomicApi::class)
    private val maxOpenStreamsBidiUpdateQueued = AtomicBoolean(false)

    @OptIn(ExperimentalAtomicApi::class)
    private val nextStreamId = AtomicInt(0)

    @OptIn(ExperimentalAtomicApi::class)
    private val maxStreamsAcceptedByPeerBidi = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val maxStreamsAcceptedByPeerUni = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val absoluteUnidirectionalStreamIdLimit = AtomicLong(Int.MAX_VALUE.toLong())

    @OptIn(ExperimentalAtomicApi::class)
    private val absoluteBidirectionalStreamIdLimit = AtomicLong(Int.MAX_VALUE.toLong())

    internal suspend fun createStream(
        connection: Connection,
        bidirectional: Boolean,
        streamHandlerFunction: (Stream) -> StreamHandler
    ): Stream {
        mutex.withLock {
            val streamId = generateStreamId(bidirectional)
            val stream = Stream(connection, streamId, streamHandlerFunction)
            streams[streamId] = stream
            return stream
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun generateStreamId(bidirectional: Boolean): Int {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-2.1:
        // "0x0  | Client-Initiated, Bidirectional"
        // "0x1  | Server-Initiated, Bidirectional"
        var id = (nextStreamId.fetchAndIncrement() shl 2)
        if (!bidirectional) {
            // "0x2  | Client-Initiated, Unidirectional |"
            // "0x3  | Server-Initiated, Unidirectional |"
            id += 0x02
        }
        return id
    }


    @OptIn(ExperimentalAtomicApi::class)
    internal suspend fun processStreamFrame(
        connection: Connection,
        frame: FrameReceived.StreamFrame
    ) {
        val streamId = frame.streamId
        var stream = mutex.withLock { streams[streamId] }
        if (stream != null) {
            stream.add(frame)
            // This implementation maintains a fixed maximum number of open streams, so when the peer closes a stream
            // it is allowed to open another.
            if (frame.isFinal && isPeerInitiated(streamId)) {
                increaseMaxOpenStreams(streamId)
            }
        } else {
            if (isPeerInitiated(streamId)) {
                if (isUni(streamId) && streamId < maxOpenStreamIdUni.load() ||
                    isBidi(streamId) && streamId < maxOpenStreamIdBidi.load()
                ) {
                    stream = Stream(
                        connection, streamId
                    ) { stream: Stream -> connection.responder().createResponder(stream) }
                    mutex.withLock {
                        streams[streamId] = stream
                    }
                    stream.add(frame)
                    if (frame.isFinal) {
                        increaseMaxOpenStreams(streamId)
                    }
                } else {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.11
                    // "An endpoint MUST terminate a connection with a STREAM_LIMIT_ERROR error
                    // if a peer opens more streams than was permitted."
                    throw TransportError(TransportError.Code.STREAM_LIMIT_ERROR)
                }
            } else {
                // happens because of timeout (local created stream -> not remote)
                debug(
                    "Receiving frame for non-existent stream " + streamId +
                            " FRAME " + frame
                )
            }
        }
    }

    internal suspend fun processMaxStreamDataFrame(frame: FrameReceived.MaxStreamDataFrame) {
        val streamId = frame.streamId
        val maxStreamData = frame.maxData

        val stream = mutex.withLock { streams[streamId] }
        if (stream != null) {
            stream.increaseMaxStreamDataAllowed(maxStreamData)
        } else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-33#section-19.10
            // "Receiving a MAX_STREAM_DATA frame for a locally-initiated stream that has not yet been created MUST
            //  be treated as a connection error of payloadType STREAM_STATE_ERROR."
            if (locallyInitiated(streamId)) {
                throw TransportError(TransportError.Code.STREAM_STATE_ERROR)
            }
        }
    }

    private fun locallyInitiated(streamId: Int): Boolean {
        return streamId % 2 == 0
    }

    internal suspend fun process(maxDataFrame: FrameReceived.MaxDataFrame) {
        // If frames are received out of order, the new max can be smaller than the current value.

        val currentMaxDataAllowed = maxDataAllowed()
        if (maxDataFrame.maxData > currentMaxDataAllowed) {
            val maxDataWasReached = currentMaxDataAllowed == maxDataAssigned()
            maxDataAllowed(maxDataFrame.maxData)
            if (maxDataWasReached) {
                val streams = mutex.withLock { this.streams.values.toList() }
                streams.forEach { stream -> stream.unblock() }
            }
        }
    }

    internal suspend fun process(stopSendingFrame: FrameReceived.StopSendingFrame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-solicited-state-transitions
        // "A STOP_SENDING frame requests that the receiving endpoint send a RESET_STREAM frame."

        val stream = mutex.withLock { streams[stopSendingFrame.streamId] }
        stream?.resetStream(stopSendingFrame.errorCode)
    }

    internal suspend fun process(resetStreamFrame: FrameReceived.ResetStreamFrame) {
        val stream = mutex.withLock { streams[resetStreamFrame.streamId] }
        stream?.terminate(resetStreamFrame.errorCode)
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun increaseMaxOpenStreams(streamId: Int) {
        if (isUni(streamId) && maxOpenStreamIdUni.load() + 4 <
            absoluteUnidirectionalStreamIdLimit.load()
        ) {
            maxOpenStreamIdUni.fetchAndAdd(4)
            if (!maxOpenStreamsUniUpdateQueued.exchange(true)) {
                sendRequestQueue(Level.App).appendRequest(createMaxStreamsUpdateUni())
            }
        } else if (isBidi(streamId) && maxOpenStreamIdBidi.load() +
            4 < absoluteBidirectionalStreamIdLimit.load()
        ) {
            maxOpenStreamIdBidi.fetchAndAdd(4)
            if (!maxOpenStreamsBidiUpdateQueued.exchange(true)) {
                sendRequestQueue(Level.App).appendRequest(createMaxStreamsUpdateBidi())
            }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun createMaxStreamsUpdateUni(): Frame {
        maxOpenStreamsUniUpdateQueued.store(false)
        // largest streamId < maxStreamId; e.g. client initiated: max-id = 6, server initiated: max-id = 7 => max streams = 1,
        return createMaxStreamsFrame(maxOpenStreamIdUni.load() / 4, false)
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun createMaxStreamsUpdateBidi(): Frame {
        maxOpenStreamsBidiUpdateQueued.store(false)

        // largest streamId < maxStreamId; e.g. client initiated: max-id = 4,
        // server initiated: max-id = 5 => max streams = 1,
        return createMaxStreamsFrame(maxOpenStreamIdBidi.load() / 4, true)
    }

    private fun isPeerInitiated(streamId: Int): Boolean {
        return streamId % 2 == (1)
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun process(frame: FrameReceived.MaxStreamsFrame) {
        if (frame.appliesToBidirectional) {
            val streamsAcceptedByPeerBidi = maxStreamsAcceptedByPeerBidi.load()
            if (frame.maxStreams > streamsAcceptedByPeerBidi) {
                maxStreamsAcceptedByPeerBidi.store(frame.maxStreams)
            }
        } else {
            val streamsAcceptedByPeerUni = maxStreamsAcceptedByPeerUni.load()
            if (frame.maxStreams > streamsAcceptedByPeerUni) {
                maxStreamsAcceptedByPeerUni.store(frame.maxStreams)
            }
        }
    }

    /**
     * Set initial max bidirectional streams that the peer will accept.
     */
    @OptIn(ExperimentalAtomicApi::class)
    fun initialMaxStreamsBidi(initialMaxStreamsBidi: Long) {
        if (initialMaxStreamsBidi >= maxStreamsAcceptedByPeerBidi.load()) {
            maxStreamsAcceptedByPeerBidi.store(initialMaxStreamsBidi)
        } else {
            debug(
                ("Attempt to reduce value of initial_max_streams_bidi from "
                        + maxStreamsAcceptedByPeerBidi + " to "
                        + initialMaxStreamsBidi + "; ignoring.")
            )
        }
    }

    /**
     * Set initial max unidirectional streams that the peer will accept.
     */
    @OptIn(ExperimentalAtomicApi::class)
    fun initialMaxStreamsUni(initialMaxStreamsUni: Long) {
        if (initialMaxStreamsUni >= maxStreamsAcceptedByPeerUni.load()) {
            maxStreamsAcceptedByPeerUni.store(initialMaxStreamsUni)
        } else {
            debug(
                ("Attempt to reduce value of initial_max_streams_uni from "
                        + maxStreamsAcceptedByPeerUni + " to " + initialMaxStreamsUni + "; ignoring.")
            )
        }
    }

    override suspend fun cleanup() {
        super.cleanup()
        val streams = mutex.withLock { this.streams.values.toList() }
        streams.forEach { stream: Stream -> stream.terminate() }

        mutex.withLock {
            this.streams.clear()
        }
    }

    suspend fun unregisterStream(streamId: Int) {
        mutex.withLock {
            streams.remove(streamId)
        }
    }

    private fun isUni(streamId: Int): Boolean {
        return streamId % 4 > 1
    }

    private fun isBidi(streamId: Int): Boolean {
        return streamId % 4 < 2
    }

}

