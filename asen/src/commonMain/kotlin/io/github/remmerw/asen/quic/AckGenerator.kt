package io.github.remmerw.asen.quic

import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.TimeSource


/**
 * Listens for received packets and generates ack frames for them.
 */
internal class AckGenerator {
    private val rangesToAcknowledge: MutableSet<Long> = ConcurrentHashMap.newKeySet()
    private val ackSentWithPacket: MutableMap<Long, List<Long>> = ConcurrentHashMap()


    @Volatile
    private var newPacketsToAcknowlegdeSince: TimeSource.Monotonic.ValueTimeMark? = null

    @OptIn(ExperimentalAtomicApi::class)
    private val acksNotSend = AtomicInt(0)


    // only invoked from the SENDER THREAD
    @OptIn(ExperimentalAtomicApi::class)
    fun mustSendAck(level: Level): Boolean {
        val acknowlegdeSince = newPacketsToAcknowlegdeSince
        if (acknowlegdeSince != null) {
            // precondition that new packages have arrived
            if (level == Level.App) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2.2
                // "A receiver SHOULD send an ACK frame after receiving at least two
                // ack-eliciting packets."

                return if (acksNotSend.load() >= Settings.ACK_FREQUENCY_TWO) {
                    true
                } else {
                    // NOTE: here is the case for 1 acknowledged packet
                    // check when the current time is greater then the first arrived package
                    // plus max ack delay, then a ack must send (returns true)
                    acknowlegdeSince.elapsedNow().inWholeMilliseconds > Settings.MAX_ACK_DELAY
                }
            }
            return true // for other level it is always without any delay
        }
        return false
    }


    // only invoked from the SENDER THREAD
    @OptIn(ExperimentalAtomicApi::class)
    fun cleanup() {
        rangesToAcknowledge.clear()
        ackSentWithPacket.clear()
        acksNotSend.store(0)
        newPacketsToAcknowlegdeSince = null
    }


    // only invoked from the RECEIVER THREAD
    @OptIn(ExperimentalAtomicApi::class)
    fun packetReceived(
        level: Level,
        isAckEliciting: Boolean,
        packetNumber: Long
    ) {
        rangesToAcknowledge.add(packetNumber)

        if (isAckEliciting) {
            if (newPacketsToAcknowlegdeSince == null) {
                newPacketsToAcknowlegdeSince = TimeSource.Monotonic.markNow()
            }

            if (level == Level.App) {
                acksNotSend.incrementAndFetch()
            }
        }
    }


    // only invoked from the RECEIVER THREAD
    fun ackFrameReceived(receivedAck: FrameReceived.AckFrame) {
        // Find max packet number that had an ack sent with it...

        var largestWithAck: Long = -1

        // it is ordered, packet status with highest packet number is at the top
        val acknowledgedRanges = receivedAck.acknowledgedRanges
        var i = 0
        while (i < acknowledgedRanges.size) {
            val to = acknowledgedRanges[i]
            i++
            val from = acknowledgedRanges[i]
            for (pn in to downTo from) {
                if (ackSentWithPacket.containsKey(pn)) {
                    largestWithAck = pn
                    break
                }
            }
            if (largestWithAck > 0) {
                break
            }
            i++
        }


        if (largestWithAck > 0) {

            // All earlier and equal sent packets (smaller-equal packet numbers), the sent ack's
            // can be discarded because their ranges are a subset of the ones from the
            // latestAcknowledgedAck and thus are now implicitly acked.
            val oldEntries: List<Long> = ackSentWithPacket.keys.filter { it ->
                it <= largestWithAck
            }.toList()


            for (old in oldEntries) {
                ackSentWithPacket.remove(old)
            }
        }
    }

    // only invoked from the SENDER THREAD
    @OptIn(ExperimentalAtomicApi::class)
    fun generateAck(packetNumber: Long, acceptLength: (Int) -> Boolean): Frame? {
        if (!rangesToAcknowledge.isEmpty()) {
            var delay = 0
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-13.2.1
            // "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately"
            val acknowlegdeSince = newPacketsToAcknowlegdeSince
            if (acknowlegdeSince != null) {
                delay = acknowlegdeSince.elapsedNow().inWholeMilliseconds.toInt()
            }

            val packets = rangesToAcknowledge.sorted()

            // Range list must not be modified during frame initialization
            // (guaranteed by this method being sync'd)
            val frame = createAckFrame(packets, delay)
            if (acceptLength.invoke(frame.frameLength())) {
                ackSentWithPacket[packetNumber] = packets
                newPacketsToAcknowlegdeSince = null
                acksNotSend.store(0)
                return frame
            }
        }
        return null
    }

}

