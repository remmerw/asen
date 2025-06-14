package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

import kotlin.random.Random

// https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions
// https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
// "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."
/**
 * Represents a ping frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-ping-frames)
 */
internal val PING: Frame = createPingFrame()

/**
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames)
 * Creates an AckFrame given a (sorted, non-adjacent) list of ranges and an ack delay.
 * ackDelay is value in milliseconds
 */
internal fun createAckFrame(packets: List<Long>, ackDelay: Int): Frame {
    val ackRanges: MutableList<ByteArray> = arrayListOf()
    var ackRangesBytesSize = 0
    var to: Long
    var ackRangesSize = 0

    var largestAcknowledgedTo: Long = 0
    var largestAcknowledgedFrom: Long = 0
    var smallest: Long = 0
    var i = packets.size - 1
    while (i >= 0) {
        to = packets[i]
        // now get the to
        var from = to
        var check = true
        while (check) {
            val index = i - 1
            if (index >= 0) {
                val value = packets[index]
                if (value == from - 1) {
                    i--
                    from = value
                } else {
                    check = false
                }
            } else {
                check = false
            }
        }

        if (ackRangesSize == 0) {
            largestAcknowledgedTo = to
            largestAcknowledgedFrom = from
        } else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
            // "Gap: A variable-length integer indicating the number of contiguous unacknowledged packets preceding the
            //  packet number one lower than the smallest in the preceding ACK Range."
            val gap =
                (smallest - to - 2).toInt() // e.g. 9..9, 5..4 => un-acked: 8, 7, 6; gap: 2
            // "ACK Range Length: A variable-length integer indicating the number of contiguous acknowledged packets
            //  preceding the largest packet number, as determined by the preceding Gap."
            //     ACK Range (..) ...,
            val distance = to - from

            val capacity =
                bytesNeeded(gap.toLong()) +
                        bytesNeeded(distance)
            val bufferAckRange = Buffer()
            encode(gap, bufferAckRange)
            encode(distance, bufferAckRange)
            require(bufferAckRange.size <= capacity)
            val arrayAckRange = bufferAckRange.readByteArray()
            ackRangesBytesSize += arrayAckRange.size
            ackRanges.add(arrayAckRange)
        }
        smallest = from
        ackRangesSize++

        i--
    }


    // ackDelay : A variable-length integer encoding the acknowledgment
    // delay in microseconds; see Section 13.2.5.  It is decoded by
    // multiplying the value in the field by 2 to the power of the
    // ack_delay_exponent transport parameter sent by the sender of the
    // ACK frame; see Section 18.2.  Compared to simply expressing the
    // delay as an integer, this encoding allows for a larger range of
    // values within the same number of bytes, at the cost of lower
    // resolution.
    val encodedAckDelay = ackDelay * 1000L / Settings.ACK_DELAY_SCALE


    // ACK frames are formatted as shown in Figure 25.
    //
    //   ACK Frame {
    //     Type (i) = 0x02..0x03,
    //     Largest Acknowledged (i),
    //     ACK Delay (i),
    //     ACK Range Count (i),
    //     First ACK Range (i),
    //     ACK Range (..) ...,
    //     [ECN Counts (..)],
    //   }
    val firstAckRange = largestAcknowledgedTo - largestAcknowledgedFrom
    val bufferSize = 1 +
            bytesNeeded(largestAcknowledgedTo) +
            bytesNeeded(encodedAckDelay) +
            bytesNeeded(ackRanges.size.toLong()) +
            bytesNeeded(firstAckRange) + ackRangesBytesSize

    val buffer = Buffer()
    buffer.writeByte(0x02.toByte()) // only AckFrame of payloadType 0x02 is supported
    encode(largestAcknowledgedTo, buffer) // Largest Acknowledged (i),
    encode(encodedAckDelay, buffer) //  ACK Delay (i),
    encode(ackRanges.size, buffer) // ACK Range Count (i)
    encode(firstAckRange, buffer) // First ACK Range (i)
    for (ackRange in ackRanges) {
        buffer.write(ackRange) //     ACK Range (..) ...,
    }

    require(buffer.size <= bufferSize)

    return Frame(FrameType.AckFrame, buffer.readByteArray())
}

/**
 * Represents a crypto frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames)
 */
internal fun createCryptoFrame(offset: Long, payload: ByteArray): Frame {
    val length = (1
            + bytesNeeded(offset)
            + bytesNeeded(payload.size.toLong())
            + payload.size)
    val buffer = Buffer()
    buffer.writeByte(0x06.toByte())
    encode(offset, buffer)
    encode(payload.size, buffer)
    buffer.write(payload)
    require(buffer.size <= length)

    return Frame(FrameType.CryptoFrame, buffer.readByteArray())
}

internal fun frameLength(streamId: Int, offset: Long, length: Int): Int {
    return (1 // frame payloadType
            + bytesNeeded(streamId.toLong())
            + bytesNeeded(offset)
            + bytesNeeded(length.toLong())
            + length)
}

internal fun createStreamFrame(
    streamId: Int, offset: Long, applicationData: ByteArray, fin: Boolean
): Frame {
    val frameLength = frameLength(streamId, offset, applicationData.size)

    val buffer = Buffer()
    val baseType = 0x08.toByte()
    var frameType =
        (baseType.toInt() or 0x04 or 0x02).toByte() // OFF-bit, LEN-bit, (no) FIN-bit
    if (fin) {
        frameType = (frameType.toInt() or 0x01).toByte()
    }
    buffer.writeByte(frameType)
    encode(streamId, buffer)
    encode(offset, buffer)
    encode(applicationData.size, buffer)
    buffer.write(applicationData)
    require(buffer.size.toInt() == frameLength)

    return Frame(FrameType.StreamFrame, buffer.readByteArray())
}

/**
 * Represents a connection close frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames)
 */
/**
 * Creates a connection close frame for a normal connection close without errors
 */
internal fun createConnectionCloseFrame(
    transportError: TransportError = TransportError(
        TransportError.Code.NO_ERROR
    )
): Frame {
    val frameType = 0x1c
    val errorCode = transportError.errorCode()

    val length = 1 +
            bytesNeeded(errorCode) +
            bytesNeeded(0) +
            bytesNeeded(0)

    val buffer = Buffer()

    buffer.writeByte(frameType.toByte())
    encode(errorCode, buffer)
    encode(0, buffer)
    encode(0, buffer)
    require(buffer.size.toInt() == length)

    return Frame(FrameType.ConnectionCloseFrame, buffer.readByteArray())
}

/**
 * Represents a data blocked frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-data_blocked-frames)
 */
internal fun createDataBlockedFrame(streamDataLimit: Long): Frame {
    val length = 1 + bytesNeeded(streamDataLimit)
    val buffer = Buffer()
    buffer.writeByte(0x14.toByte())
    encode(streamDataLimit, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.DataBlockedFrame, buffer.readByteArray())
}

/**
 * Represents a stream data blocked frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frames)
 */
internal fun createStreamDataBlockedFrame(streamId: Int, streamDataLimit: Long): Frame {
    val length = (1 + bytesNeeded(streamId.toLong())
            + bytesNeeded(streamDataLimit))
    val buffer = Buffer()
    buffer.writeByte(0x15.toByte())
    encode(streamId, buffer)
    encode(streamDataLimit, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.StreamDataBlockedFrame, buffer.readByteArray())
}

internal fun createMaxDataFrame(maxData: Long): Frame {
    val length = 1 + bytesNeeded(maxData)
    val buffer = Buffer()
    buffer.writeByte(0x10.toByte())
    encode(maxData, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.MaxDataFrame, buffer.readByteArray())
}

private fun createPingFrame(): Frame {
    val buffer = Buffer()
    buffer.writeByte(0x01.toByte())
    return Frame(FrameType.PingFrame, buffer.readByteArray())
}

/**
 * Represents a number of consecutive padding frames.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames)
 *
 *
 * Usually, padding will consist of multiple padding frames, each being exactly one (zero) byte. This class can
 * represent an arbitrary number of consecutive padding frames, by recording padding length.
 */
internal fun createPaddingFrame(length: Int): Frame {
    return Frame(FrameType.PaddingFrame, ByteArray(length))
}

/**
 * Represents a new token frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_token-frames)
 */
@Suppress("unused")
internal fun createNewTokenFrame(token: ByteArray): Frame {
    val length = 1 + bytesNeeded(token.size.toLong()) + token.size
    val buffer = Buffer()
    buffer.writeByte(0x07.toByte())
    encode(token.size, buffer)
    buffer.write(token)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.NewTokenFrame, buffer.readByteArray())
}

/**
 * Represents a reset stream frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames)
 */
internal fun createResetStreamFrame(streamId: Int, errorCode: Long, finalSize: Long): Frame {
    val length = (1
            + bytesNeeded(streamId.toLong())
            + bytesNeeded(errorCode)
            + bytesNeeded(finalSize))
    val buffer = Buffer()
    buffer.writeByte(0x04.toByte())
    encode(streamId, buffer)
    encode(errorCode, buffer)
    encode(finalSize, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.ResetStreamFrame, buffer.readByteArray())
}

/**
 * Represents a max stream data frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames)
 */
internal fun createMaxStreamDataFrame(streamId: Int, maxData: Long): Frame {
    val length = 1 +
            bytesNeeded(streamId.toLong()) +
            bytesNeeded(maxData)
    val buffer = Buffer()

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames
    // "The MAX_STREAM_DATA frame (payloadType=0x11)..."
    buffer.writeByte(0x11.toByte())
    encode(streamId, buffer)
    encode(maxData, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.MaxStreamDataFrame, buffer.readByteArray())
}

/**
 * Represents a max streams frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frames)
 */
internal fun createMaxStreamsFrame(
    maxStreams: Long,
    appliesToBidirectional: Boolean
): Frame {
    val length = 1 + bytesNeeded(maxStreams)
    val buffer = Buffer()
    buffer.writeByte((if (appliesToBidirectional) 0x12 else 0x13).toByte())
    encode(maxStreams, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.MaxStreamsFrame, buffer.readByteArray())
}

/**
 * Represents a new connection id frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames)
 */
internal fun createNewConnectionIdFrame(sequenceNr: Int, retirePriorTo: Int, cid: Int): Frame {
    val statelessResetToken = ByteArray(16)
    Random.nextBytes(statelessResetToken)

    val length = (1 + bytesNeeded(sequenceNr.toLong())
            + bytesNeeded(retirePriorTo.toLong())
            + 1 + Int.SIZE_BYTES + 16)
    val buffer = Buffer()

    buffer.writeByte(0x18.toByte())
    encode(sequenceNr, buffer)
    encode(retirePriorTo, buffer)
    buffer.writeByte(Int.SIZE_BYTES.toByte())
    buffer.writeInt(cid)
    buffer.write(statelessResetToken)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.NewConnectionIdFrame, buffer.readByteArray())
}

/**
 * Represents a path challenge frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames)
 */
@Suppress("unused")
internal fun createPathChallengeFrame(data: ByteArray): Frame {
    val buffer = Buffer()
    buffer.writeByte(0x1a.toByte())
    buffer.write(data)
    return Frame(FrameType.PathChallengeFrame, buffer.readByteArray())
}

/**
 * Represents a path response frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_response-frames)
 */
internal fun createPathResponseFrame(data: ByteArray): Frame {
    val buffer = Buffer()
    buffer.writeByte(0x1b.toByte())
    buffer.write(data)
    return Frame(FrameType.PathResponseFrame, buffer.readByteArray())
}

/**
 * Represents a retire connection id frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames)
 */
internal fun createRetireConnectionsIdFrame(sequenceNumber: Int): Frame {
    val length = 1 + bytesNeeded(sequenceNumber.toLong())
    val buffer = Buffer()
    buffer.writeByte(0x19.toByte())
    encode(sequenceNumber, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.RetireConnectionIdFrame, buffer.readByteArray())
}

/**
 * Represents a stop sending frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames)
 */
internal fun createStopSendingFrame(streamId: Int, errorCode: Long): Frame {
    val length = (1 + bytesNeeded(streamId.toLong()) + bytesNeeded(errorCode))
    val buffer = Buffer()
    buffer.writeByte(0x05.toByte())
    encode(streamId, buffer)
    encode(errorCode, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.StopSendingFrame, buffer.readByteArray())
}

/**
 * Represents a streams blocked frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames)
 */
@Suppress("unused")
internal fun createStreamsBlockedFrame(bidirectional: Boolean, streamLimit: Int): Frame {
    val length = 1 +
            bytesNeeded(streamLimit.toLong())
    val buffer = Buffer()
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames
    // "A STREAMS_BLOCKED frame of payloadType 0x16 is used to indicate reaching the bidirectional stream limit, and a
    // STREAMS_BLOCKED frame of payloadType 0x17 is used to indicate reaching the unidirectional stream limit."
    buffer.writeByte(if (bidirectional) 0x16.toByte() else 0x17.toByte())
    encode(streamLimit, buffer)
    require(buffer.size.toInt() == length)
    return Frame(FrameType.StreamsBlockedFrame, buffer.readByteArray())
}


/**
 * Returns whether the frame is ack eliciting
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions)
 * "Ack-eliciting packet: A QUIC packet that contains frames other than ACK, PADDING, and CONNECTION_CLOSE."
 *
 * @return true when the frame is ack-eliciting
 */

internal fun isAckEliciting(frame: Frame): Boolean {
    return when (frame.frameType) {
        FrameType.AckFrame, FrameType.PaddingFrame, FrameType.ConnectionCloseFrame -> false
        else -> true
    }
}