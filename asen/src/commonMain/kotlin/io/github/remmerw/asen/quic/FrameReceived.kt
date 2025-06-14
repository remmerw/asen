package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import kotlinx.io.Buffer
import kotlinx.io.readByteArray


internal interface FrameReceived {
    /**
     * Represents a connection close frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames)
     */

    @Suppress("ArrayInDataClass")
    data class ConnectionCloseFrame(
        val frameType: Int,
        val triggeringFrameType: Int,
        val reasonPhrase: ByteArray?,
        val errorCode: Long,
        val tlsError: Int
    ) : FrameReceived {
        fun hasTransportError(): Boolean {
            return frameType == 0x1c && errorCode != 0L
        }

        fun hasTlsError(): Boolean {
            return tlsError != -1
        }

        fun hasReasonPhrase(): Boolean {
            return reasonPhrase != null
        }

        fun hasApplicationProtocolError(): Boolean {
            return frameType == 0x1d && errorCode != 0L
        }

        fun hasError(): Boolean {
            return hasTransportError() || hasApplicationProtocolError()
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "...  a default value of 3 is assumed (indicating a multiplier of 8)."

    @Suppress("ArrayInDataClass")
    data class AckFrame(
        val acknowledgedRanges: LongArray, val largestAcknowledged: Long,
        val ackDelay: Int
    ) : FrameReceived

    /**
     * Represents a crypto frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames)
     */

    @Suppress("ArrayInDataClass")
    data class CryptoFrame(val offset: Long, val payload: ByteArray, val length: Int) :
        FrameReceived,
        Comparable<CryptoFrame> {
        fun offsetLength(): Long {
            return offset + length
        }

        override fun compareTo(other: CryptoFrame): Int {
            return if (this.offset == other.offset) {
                length.compareTo(other.length)
            } else {
                this.offset.compareTo(other.offset)
            }
        }
    }

    /**
     * Represents a data blocked frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-data_blocked-frames)
     */

    data class DataBlockedFrame(val streamDataLimit: Long) : FrameReceived


    // https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-19.9

    data class MaxDataFrame(val maxData: Long) : FrameReceived

    /**
     * Represents a max stream data frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames)
     */

    data class MaxStreamDataFrame(val streamId: Int, val maxData: Long) : FrameReceived

    /**
     * Represents a max streams frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frames)
     */

    data class MaxStreamsFrame(
        val maxStreams: Long,
        val appliesToBidirectional: Boolean
    ) : FrameReceived

    /**
     * Represents a new connection id frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames)
     */

    @Suppress("ArrayInDataClass")
    data class NewConnectionIdFrame(
        val sequenceNr: Int, val retirePriorTo: Int, val connectionId: Number,
        val statelessResetToken: ByteArray
    ) : FrameReceived

    /**
     * Represents a number of consecutive padding frames.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames)
     *
     *
     * Usually, padding will consist of multiple padding frames, each being exactly one (zero) byte. This class can
     * represent an arbitrary number of consecutive padding frames, by recording padding length.
     */

    data class PaddingFrame(val length: Int) : FrameReceived

    /**
     * Represents a path challenge frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames)
     */
    @Suppress("ArrayInDataClass")
    data class PathChallengeFrame(val data: ByteArray) : FrameReceived

    /**
     * Represents a path response frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-path_response-frames)
     */

    @Suppress("ArrayInDataClass")
    data class PathResponseFrame(val data: ByteArray) : FrameReceived

    /**
     * Represents a ping frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-ping-frames)
     */
    @Suppress("unused")
    class PingFrame : FrameReceived

    /**
     * Represents a reset stream frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames)
     */

    data class ResetStreamFrame(val streamId: Int, val errorCode: Long, val finalSize: Long) :
        FrameReceived

    /**
     * Represents a retire connection id frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames)
     */

    data class RetireConnectionIdFrame(val sequenceNumber: Int) : FrameReceived

    /**
     * Represents a stop sending frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames)
     */

    data class StopSendingFrame(val streamId: Int, val errorCode: Long) : FrameReceived

    /**
     * Represents a stream data blocked frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frames)
     */

    data class StreamDataBlockedFrame(val streamId: Int, val streamDataLimit: Long) : FrameReceived

    @Suppress("ArrayInDataClass")
    data class StreamFrame(
        val streamId: Int,
        val isFinal: Boolean,
        val offset: Long,
        val length: Int,
        val streamData: ByteArray
    ) :
        FrameReceived, Comparable<StreamFrame> {
        override fun compareTo(other: StreamFrame): Int {
            return if (this.offset == other.offset) {
                length.compareTo(other.length)
            } else {
                offset.compareTo(other.offset)
            }
        }

        fun offsetLength(): Long {
            return offset + length
        }
    }

    /**
     * Represents a streams blocked frame.
     * [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames)
     */

    data class StreamsBlockedFrame(val bidirectional: Boolean, val streamLimit: Int) : FrameReceived

    companion object {

        fun parseStreamsBlockedFrame(type: Byte, buffer: Buffer): StreamsBlockedFrame {
            return StreamsBlockedFrame(
                type.toInt() == 0x16,
                parseLong(buffer).toInt()
            )
        }


        fun parseConnectionCloseFrame(type: Byte, buffer: Buffer): ConnectionCloseFrame {
            var triggeringFrameType = 0
            val errorCode = parseLong(buffer)
            if (type.toInt() == 0x1c) {
                triggeringFrameType = parseInt(buffer)
            }
            var reasonPhrase = Settings.BYTES_EMPTY
            val reasonPhraseLength = parseInt(buffer)
            if (reasonPhraseLength > 0) {
                reasonPhrase = buffer.readByteArray(reasonPhraseLength)
            }
            var tlsError = -1
            if (type.toInt() == 0x1c && errorCode >= 0x0100 && errorCode < 0x0200) {
                tlsError = (errorCode - 256).toInt()
            }

            return ConnectionCloseFrame(
                type.toInt(), triggeringFrameType, reasonPhrase,
                errorCode, tlsError
            )
        }


        fun parseAckFrame(type: Byte, buffer: Buffer, delayScale: Int): AckFrame {
            //  If the frame payloadType is 0x03, ACK frames also contain the cumulative count
            //  of QUIC packets with associated ECN marks received on the connection
            //  up until this point.

            if (type.toInt() == 0x03) {
                debug("AckFrame of payloadType 0x03 is not yet fully supported")
            }


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


            // A variable length integer is an encoding of 64-bit unsigned
            // integers into between 1 and 9 bytes.

            // A variable-length integer representing the
            // largest packet number the peer is acknowledging; this is usually
            // the largest packet number that the peer has received prior to
            // generating the ACK frame.  Unlike the packet number in the QUIC
            //long or short header, the value in an ACK frame is not truncated.
            val largestAcknowledged = parseLong(buffer)

            // Parse as long to protect to against buggy peers. Convert to int as MAX_INT is large enough to hold the
            // largest ack delay that makes sense (even with an delay exponent of 0, MAX_INT is approx 2147 seconds, approx. half an hour).
            val ackDelay = (parseLong(buffer).toInt() * delayScale) / 1000

            val ackBlockCount = parseLong(buffer).toInt()

            val acknowledgedRanges = LongArray((ackBlockCount + 1) * 2)

            var currentSmallest = largestAcknowledged
            // The smallest of the first block is the largest - (rangeSize - 1).
            val rangeSize = 1 + parseInt(buffer)
            var acknowledgedRangesIndex = 0
            acknowledgedRanges[acknowledgedRangesIndex] = largestAcknowledged
            acknowledgedRangesIndex++
            acknowledgedRanges[acknowledgedRangesIndex] = largestAcknowledged - rangeSize - 1
            currentSmallest -= (rangeSize - 1).toLong()

            repeat(ackBlockCount) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
                // "Each Gap indicates a range of packets that are not being
                //   acknowledged.  The number of packets in the gap is one higher than
                //   the encoded value of the Gap Field."
                val gapSize = parseInt(buffer) + 1
                // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
                // "Each ACK Block acknowledges a contiguous range of packets by
                //   indicating the number of acknowledged packets that precede the
                //   largest packet number in that block.  A value of zero indicates that
                //   only the largest packet number is acknowledged."
                val contiguousPacketsPreceding = parseInt(buffer) + 1
                // The largest of the next range is the current smallest - (gap size + 1), because the gap size counts the
                // ones not being present, and we need the first (below) being present.
                // The new current smallest is largest of the next range - (range size - 1)
                //                             == current smallest - (gap size + 1) - (range size - 1)
                //                             == current smallest - gap size - range size
                val largestOfRange = currentSmallest - gapSize - 1

                acknowledgedRangesIndex++
                acknowledgedRanges[acknowledgedRangesIndex] = largestOfRange

                acknowledgedRangesIndex++
                acknowledgedRanges[acknowledgedRangesIndex] =
                    largestOfRange - contiguousPacketsPreceding + 1

                currentSmallest -= (gapSize + contiguousPacketsPreceding).toLong()
            }

            // ECN Counts {
            //     ECT0 Count (i),
            //     ECT1 Count (i),
            //     ECN-CE Count (i),
            //   }
            //
            //                        Figure 27: ECN Count Format
            //
            //   The three ECN Counts are:
            //
            //   ECT0 Count:  A variable-length integer representing the total number
            //      of packets received with the ECT(0) codepoint in the packet number
            //      space of the ACK frame.
            //
            //   ECT1 Count:  A variable-length integer representing the total number
            //      of packets received with the ECT(1) codepoint in the packet number
            //      space of the ACK frame.
            //
            //   CE Count:  A variable-length integer representing the total number of
            //      packets received with the CE codepoint in the packet number space
            //      of the ACK frame.
            //
            //   ECN counts are maintained separately for each packet number space.
            return AckFrame(acknowledgedRanges, largestAcknowledged, ackDelay)
        }


        fun parseCryptoFrame(buffer: Buffer): CryptoFrame {
            val offset = parseLong(buffer)
            val length = parseInt(buffer)

            val cryptoData = buffer.readByteArray(length)
            return CryptoFrame(offset, cryptoData, length)
        }


        fun parseDataBlockedFrame(buffer: Buffer): DataBlockedFrame {
            return DataBlockedFrame(parseLong(buffer))
        }


        fun parseMaxDataFrame(buffer: Buffer): MaxDataFrame {
            return MaxDataFrame(parseLong(buffer))
        }


        fun parseMaxStreamDataFrame(buffer: Buffer): MaxStreamDataFrame {
            return MaxStreamDataFrame(
                parseLong(buffer).toInt(),
                parseLong(buffer)
            )
        }


        fun parseMaxStreamsFrame(type: Byte, buffer: Buffer): MaxStreamsFrame {
            return MaxStreamsFrame(
                parseLong(buffer),
                type.toInt() == 0x12
            )
        }


        fun parseNewConnectionIdFrame(buffer: Buffer): NewConnectionIdFrame {
            val sequenceNr = parseInt(buffer)
            val retirePriorTo = parseInt(buffer)
            val length = buffer.readByte().toInt()
            if (length != Int.SIZE_BYTES) {
                error("not supported length of connection id")
            }
            val cid = buffer.readInt()

            val statelessResetToken = buffer.readByteArray(16)

            return NewConnectionIdFrame(sequenceNr, retirePriorTo, cid, statelessResetToken)
        }


        fun parseNewTokenFrame(buffer: Buffer) {
            val tokenLength = parseInt(buffer)
            buffer.skip(tokenLength.toLong()) // new Token
        }

        /**
         * Strictly speaking, a padding frame consists of one single byte. For convenience,
         * here all subsequent padding bytes are collected in one padding object.
         */
        fun parsePaddingFrame(buffer: Buffer): PaddingFrame {
            var length = 0

            while (buffer.peek().readByte().toInt() == 0) {
                buffer.skip(1)
                length++
            }

            return PaddingFrame(length)
        }

        fun parsePathChallengeFrame(buffer: Buffer): PathChallengeFrame {
            val data = buffer.readByteArray(8)
            return PathChallengeFrame(data)
        }

        fun parsePathResponseFrame(buffer: Buffer): PathResponseFrame {
            val data = buffer.readByteArray(8)
            return PathResponseFrame(data)
        }


        fun parseResetStreamFrame(buffer: Buffer): ResetStreamFrame {
            val streamId = parseInt(buffer)
            val errorCode = parseLong(buffer)
            val finalSize = parseLong(buffer)
            return ResetStreamFrame(streamId, errorCode, finalSize)
        }


        fun parseRetireConnectionIdFrame(buffer: Buffer): RetireConnectionIdFrame {
            val sequenceNr = parseInt(buffer)
            return RetireConnectionIdFrame(sequenceNr)
        }


        fun parseStopSendingFrame(buffer: Buffer): StopSendingFrame {
            val streamId = parseInt(buffer)
            val errorCode = parseLong(buffer)

            return StopSendingFrame(streamId, errorCode)
        }


        fun parseStreamDataBlockedFrame(buffer: Buffer): StreamDataBlockedFrame {
            val streamId = parseInt(buffer)
            val streamDataLimit = parseLong(buffer)

            return StreamDataBlockedFrame(streamId, streamDataLimit)
        }


        fun parseStreamFrame(type: Byte, buffer: Buffer): StreamFrame {
            val withOffset = ((type.toInt() and 0x04) == 0x04)
            val withLength = ((type.toInt() and 0x02) == 0x02)
            val isFinal = ((type.toInt() and 0x01) == 0x01)

            val streamId = parseInt(buffer)

            var offset: Long = 0
            if (withOffset) {
                offset = parseLong(buffer)
            }
            val length = if (withLength) {
                parseInt(buffer)
            } else {
                buffer.size.toInt()
            }

            val streamData = buffer.readByteArray(length)

            return StreamFrame(streamId, isFinal, offset, length, streamData)
        }

    }
}

