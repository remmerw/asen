package io.github.remmerw.asen.quic


/**
 * Assembles QUIC packets for a given encryption level, based on "send requests" that are previously queued.
 * These send requests either contain a frame, or can produce a frame to be sent.
 */
internal class PacketAssembler internal constructor(
    private val version: Int,
    private val level: Level,
    private val sendRequestQueue: SendRequestQueue,
    private val ackGenerator: AckGenerator
) {
    private var packetNumberGenerator = 0L // no concurrency


    /**
     * Assembles a QUIC packet for the encryption level handled by this instance.
     *
     * @param scid can be null when encryption level is 1-rtt; but not for the other levels; can be empty array though
     */
    suspend fun assemble(
        remainingCwndSize: Int,
        availablePacketSize: Int,
        scid: Number?,
        dcid: Number?
    ): Packet? {
        if (level == Level.Initial && availablePacketSize < 1200) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to
            // at least the smallest
            //  allowed maximum datagram size of 1200 bytes... "
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying
            // ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."
            // Note that in case of an initial packet, the availablePacketSize equals the
            // maximum datagram size; even
            // when different packets are coalesced, the initial packet is always the
            // first that is assembled.
            return null
        }
        // Packet can be 3 bytes larger than estimated size because of unknown packet number length.
        val available = kotlin.math.min(remainingCwndSize, availablePacketSize - 3)
        val frames: MutableList<Frame> = arrayListOf()

        val packetNumber = packetNumberGenerator++

        val dcidLength = lengthNumber(dcid)

        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed
        if (ackGenerator.mustSendAck(level)) {
            val ackFrame = ackGenerator.generateAck(
                packetNumber
            ) { length: Int ->
                estimateLength(
                    level, dcidLength,
                    frames, length
                ) <= availablePacketSize
            }

            // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2
            // "... packets containing only ACK frames are not congestion controlled ..."
            // So: only check if it fits within available packet space
            if (ackFrame != null) {
                frames.add(ackFrame)
            } else {
                // If not even a mandatory ack can be added, don't bother about other frames:
                // theoretically there might be frames
                // that can be fit, but this is very unlikely to happen (because limit packet size
                // is caused by coalescing packets
                // in one datagram, which will only happen during handshake, when acks are still
                // small) and even then: there
                // will be a next packet in due time.
                // AckFrame does not fit in availablePacketSize, so just return;
                return null
            }
        }

        if (sendRequestQueue.hasRequests()) {
            // Must create packet here, to have an initial estimate of packet header overhead
            var estimatedSize = estimateLength(
                level,
                dcidLength, frames, 1000
            ) - 1000 // Estimate length if large

            // frame would have been added; this will give upper limit of packet overhead.
            while (estimatedSize < available) {
                // First try to find a frame that will leave space for optional frame (if any)
                val proposedSize = available - estimatedSize
                val next = sendRequestQueue.next(proposedSize)
                    ?: // Nothing fits within available space
                    break

                val nextFrame = next.frameSupplier.nextFrame(proposedSize)
                if (nextFrame != null) {
                    check(nextFrame.frameLength() <= proposedSize) {
                        ("supplier does not produce frame of right (max) size: " +
                                nextFrame.frameLength() + " > " + (proposedSize)
                                + " frame: " + nextFrame)
                    }
                    estimatedSize += nextFrame.frameLength()
                    frames.add(nextFrame)
                }
            }
        }


        val packet: Packet?
        if (frames.isEmpty()) {
            // Nothing could be added, discard packet and mark packet number as not used
            packetNumberGenerator--
            packet = null
        } else {
            addPadding(level, dcidLength, frames)
            packet = createPacket(
                version,
                level, packetNumber, scid, dcid, frames
            )
        }
        return packet
    }


    private fun addPadding(level: Level, dcidLength: Int, frames: MutableList<Frame>) {
        if (level == Level.Initial) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest
            //  allowed maximum datagram size of 1200 bytes... "
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."

            val requiredPadding = 1200 - estimateLength(
                level, dcidLength, frames,
                0
            )
            if (requiredPadding > 0) {
                frames.add(createPaddingFrame(requiredPadding))
            }
        }
        if (hasPathChallengeOrResponse(frames)) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-8.2.1
            // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes."
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-8.2.2
            // "An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed
            // maximum datagram size of 1200 bytes."


            val requiredPadding = 1200 - estimateLength(
                level,
                dcidLength, frames, 0
            )
            if (requiredPadding > 0) {
                frames.add(createPaddingFrame(requiredPadding))
            }
        }
    }

    private fun createPacket(
        version: Int, level: Level, packetNumber: Long,
        scid: Number?, dcid: Number?, frames: List<Frame>
    ): Packet {
        return when (level) {
            Level.App -> PacketService.createShortHeader(version, frames, packetNumber, dcid!!)
            Level.Handshake -> PacketService.createHandshake(
                version, frames,
                packetNumber, scid!!, dcid!!
            )

            Level.Initial -> PacketService.createInitial(
                version, frames,
                packetNumber, scid!!, dcid!!
            )
        }
    }

    private fun framesLength(frames: List<Frame>): Int {
        var sum = 0
        for (frame in frames) {
            sum += frame.frameLength()
        }
        return sum
    }

    private fun hasPathChallengeOrResponse(frames: List<Frame>): Boolean {
        for ((frameType) in frames) {
            if (frameType == FrameType.PathResponseFrame
                || frameType == FrameType.PathChallengeFrame
            ) {
                return true
            }
        }
        return false
    }

    /**
     * Estimates what the length of this packet will be after it has been encrypted. The returned length must be
     * less then or equal the actual length after encryption. Length estimates are used when preparing packets for
     * sending, where certain limits must be met (e.g. congestion control, max datagram size, ...).
     *
     * @param additionalPayload when not 0, estimate the length if this amount of additional (frame) bytes were added.
     */
    private fun estimateLength(
        level: Level, dcidLength: Int,
        frames: List<Frame>, additionalPayload: Int
    ): Int {
        return when (level) {
            Level.App -> estimateShortHeaderPacketLength(
                dcidLength,
                frames, additionalPayload
            )

            Level.Handshake -> estimateHandshakePacketLength(
                dcidLength, frames, additionalPayload
            )

            Level.Initial -> estimateInitialPacketLength(
                dcidLength, frames, additionalPayload
            )
        }
    }

    private fun estimateShortHeaderPacketLength(
        dcidLength: Int,
        frames: List<Frame>,
        additionalPayload: Int
    ): Int {
        val payloadLength = framesLength(frames) + additionalPayload
        return (1
                + dcidLength
                + 1 // packet number length: will usually be just 1, actual value
                // cannot be computed until packet number is known
                + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16)
    }

    private fun estimateHandshakePacketLength(
        dcidLength: Int,
        frames: List<Frame>,
        additionalPayload: Int
    ): Int {
        val payloadLength = framesLength(frames) + additionalPayload
        return (1
                + 4
                + 1 + dcidLength
                + 1 + Int.SIZE_BYTES // scid
                + (if (payloadLength + 1 > 63) 2 else 1)
                + 1 // packet number length: will usually be just 1, actual value cannot be
                // computed until packet number is known
                + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16)
    }

    private fun estimateInitialPacketLength(
        dcidLength: Int, frames: List<Frame>,
        additionalPayload: Int
    ): Int {
        val payloadLength = framesLength(frames) + additionalPayload
        return (1
                + 4
                + 1 + dcidLength
                + 1 + Int.SIZE_BYTES // scid
                + 1 // token length, which is not supported
                + (if (payloadLength + 1 > 63) 2 else 1)
                + 1 // packet number length: will usually be just 1, actual value cannot be
                // computed until packet number is known
                + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16)
    }

}

