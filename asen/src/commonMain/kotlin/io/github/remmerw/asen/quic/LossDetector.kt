package io.github.remmerw.asen.quic

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.math.max

internal class LossDetector(private val connectionFlow: ConnectionFlow) {
    private val packetSentLog: MutableMap<Long, PacketStatus> = mutableMapOf()
    private val mutex = Mutex()

    @OptIn(ExperimentalAtomicApi::class)
    private val largestAcked = AtomicLong(-1L)

    @Volatile
    private var isStopped = false

    suspend fun packetSent(packetStatus: PacketStatus) {
        if (isStopped) {
            return
        }

        // During a reset operation, no new packets must be logged as sent.
        mutex.withLock {
            packetSentLog[packetStatus.packet.packetNumber()] = packetStatus
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    suspend fun processAckFrameReceived(ackFrame: FrameReceived.AckFrame) {
        if (isStopped) {
            return
        }


        largestAcked.store(max(largestAcked.load(), ackFrame.largestAcknowledged))


        var newlyAcked: PacketStatus? = null

        // it is ordered, packet status with highest packet number is at the top
        val acknowledgedRanges = ackFrame.acknowledgedRanges
        var i = 0
        while (i < acknowledgedRanges.size) {
            val to = acknowledgedRanges[i]
            i++
            val from = acknowledgedRanges[i]
            for (pn in to downTo from) {
                val packetStatus = mutex.withLock { packetSentLog.remove(pn) }
                if (packetStatus != null) {
                    if (isAckEliciting(packetStatus.packet)) {
                        connectionFlow.processAckedPacket(packetStatus)
                    }
                    if (newlyAcked == null) {
                        newlyAcked = packetStatus
                    }
                }
            }
            i++
        }

        // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-5.1
        // "An endpoint generates an RTT sample on receiving an ACK frame that meets the following
        // two conditions:
        // the largest acknowledged packet number is newly acknowledged, and
        // at least one of the newly acknowledged packets was ack-eliciting."
        if (newlyAcked != null) {
            if (newlyAcked.packet.packetNumber() == ackFrame.largestAcknowledged) {
                if (isAckEliciting(newlyAcked.packet)) { // at least one of the newly acknowledged packets was ack-eliciting."
                    connectionFlow.addSample(newlyAcked.timeSent, ackFrame.ackDelay)
                }
            }
        }
    }

    suspend fun stop() {
        isStopped = true


        val packets = mutex.withLock { packetSentLog.values.toList() }
        packets.forEach { packetStatus ->
            connectionFlow.discardBytesInFlight(packetStatus)
        }
        mutex.withLock {
            packetSentLog.clear()
        }
    }

    suspend fun detectLostPackets() {
        if (isStopped) {
            return
        }

        val lossDelay = (Settings.TIME_THRESHOLD * max(
            connectionFlow.getSmoothedRtt(), connectionFlow.getLatestRtt()
        )).toLong()


        // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-6.1
        // "A packet is declared lost if it meets all the following conditions:
        //   o  The packet is unacknowledged, in-flight, and was sent prior to an
        //      acknowledged packet.
        //   o  Either its packet number is kPacketThreshold smaller than an
        //      acknowledged packet (Section 6.1.1), or it was sent long enough in
        //      the past (Section 6.1.2)."
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-2
        // "In-flight:  Packets are considered in-flight when they have been sent
        //      and neither acknowledged nor declared lost, and they are not ACK-
        //      only."
        val packets = mutex.withLock {
            packetSentLog.values.toList()
        }
        packets.forEach { packetStatus ->
            if (pnTooOld(packetStatus) || sentTimeTooLongAgo(packetStatus, lossDelay)) {
                if (!packetStatus.packet.isAckOnly) {
                    declareLost(packetStatus)
                }
            }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun pnTooOld(p: PacketStatus): Boolean {
        val kPacketThreshold = 3
        return p.packet.packetNumber() <= largestAcked.load() - kPacketThreshold
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun sentTimeTooLongAgo(p: PacketStatus, lossDelay: Long): Boolean {
        return p.packet.packetNumber() <= largestAcked.load()
                && p.timeSent.elapsedNow().inWholeMilliseconds > lossDelay
    }

    private suspend fun declareLost(packetStatus: PacketStatus) {
        if (isAckEliciting(packetStatus.packet)) {
            connectionFlow.registerLost(packetStatus)
        }

        // Retransmitting the frames in the lost packet is delegated to the lost frame callback,
        // because whether retransmitting the frame is necessary (and in which manner) depends
        // on frame payloadType,
        // see https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-13.3
        val frames = packetStatus.packet.frames()
        for (frame in frames) {
            when (frame.frameType) {
                FrameType.MaxStreamsFrame, FrameType.MaxStreamDataFrame, FrameType.StopSendingFrame,
                FrameType.ResetStreamFrame, FrameType.RetireConnectionIdFrame, FrameType.StreamFrame,
                FrameType.MaxDataFrame, FrameType.HandshakeDoneFrame -> connectionFlow.insertRequest(
                    packetStatus.packet.level(),
                    frame
                )

                FrameType.CryptoFrame,
                FrameType.NewConnectionIdFrame,
                FrameType.DataBlockedFrame,
                FrameType.StreamDataBlockedFrame -> connectionFlow.addRequest(
                    packetStatus.packet.level(),
                    frame
                )

                else -> {}
            }
        }
        mutex.withLock {
            packetSentLog.remove(packetStatus.packet.packetNumber())
        }
    }
}
