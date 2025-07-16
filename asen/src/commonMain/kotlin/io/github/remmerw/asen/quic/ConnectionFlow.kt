package io.github.remmerw.asen.quic

import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.math.abs
import kotlin.math.max
import kotlin.time.TimeSource


/**
 * This class implements the flow concepts of a QUIC connection
 * -> RttEstimator
 *
 *
 * -> CongestionController
 * [...](https://datatracker.ietf.org/doc/html/rfc9002#name-congestion-control)
 * -> RecoveryManager
 * QUIC Loss Detection is specified in [...](https://www.rfc-editor.org/rfc/rfc9002.html).
 *
 *
 * "QUIC senders use acknowledgments to detect lost packets and a PTO to ensure acknowledgments are received"
 * It uses a single timer, because either there are lost packets to detect, or a probe must be scheduled, never both.
 *
 *
 * **Ack based loss detection**
 * When an Ack is received, packets that are sent "long enough" before the largest acked, are deemed lost; for the
 * packets not send "long enough", a timer is set to mark them as lost when "long enough" time has been passed.
 *
 *
 * An example:
 * -----------------------time------------------->>
 * sent:   1           2      3        4
 * acked:                                    4
 * \--- long enough before 4 --/                       => 1 is marked lost immediately
 * \--not long enough before 4 --/
 * |
 * Set timer at this point in time, as that will be "long enough".
 * At that time, a new timer will be set for 3, unless acked meanwhile.
 *
 *
 * **Detecting tail loss with probe timeout**
 * When no Acks arrive, no packets will be marked as lost. To trigger the peer to send an ack (so loss detection can do
 * its job again), a probe (ack-eliciting packet) will be sent after the probe timeout. If the situation does not change
 * (i.e. no Acks received), additional probes will be sent, but with an exponentially growing delay.
 *
 *
 * An example:
 * -----------------------time------------------->>
 * sent:   1           2      3        4
 * acked:                                    4
 * \-- timer set at loss time  --/
 * |
 * When the timer fires, there is no new ack received, so
 * nothing can be marked as lost. A probe is scheduled for
 * "probe timeout" time after the time 3 was sent:
 * \-- timer set at "probe timeout" time after 3 was sent --\
 * |
 * Send probe!
 *
 *
 * Note that packet 3 will not be marked as lost as long no ack is received!
 *
 *
 * **Exceptions**
 * Because a server might be blocked by the anti-amplification limit, a client must also send probes when it has no
 * ack eliciting packets in flight, but is not sure whether the peer has validated the client address.
 */

open class ConnectionFlow(version: Int) : ConnectionSecrets(version) {
    private val sendRequestQueues = arrayOfNulls<SendRequestQueue>(Level.LENGTH)
    private val packetAssemblers = arrayOfNulls<PacketAssembler>(Level.LENGTH)
    private val ackGenerators = arrayOfNulls<AckGenerator>(Level.LENGTH)
    private val discardedLevels = arrayOfNulls<Boolean>(Level.LENGTH)
    private val cryptoStreams = arrayOfNulls<CryptoStream>(Level.LENGTH)

    @OptIn(ExperimentalAtomicApi::class)
    private val maxDataAssigned = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val rttVar = AtomicInt(Settings.NOT_DEFINED)

    @OptIn(ExperimentalAtomicApi::class)
    private val smoothedRtt = AtomicInt(Settings.NOT_DEFINED)

    @OptIn(ExperimentalAtomicApi::class)
    private val minRtt = AtomicInt(Int.MAX_VALUE)

    @OptIn(ExperimentalAtomicApi::class)
    private val latestRtt = AtomicInt(0)

    @OptIn(ExperimentalAtomicApi::class)
    private val bytesInFlight = AtomicLong(0L)

    @OptIn(ExperimentalAtomicApi::class)
    private val congestionWindow = AtomicLong(Settings.INITIAL_CONGESTION_WINDOW.toLong())
    private val lossDetectors = arrayOfNulls<LossDetector>(Level.LENGTH)

    // https://tools.ietf.org/html/draft-ietf-quic-transport-30#section-8.2
    // "If this value is absent, a default of 25 milliseconds is assumed."
    @Volatile
    protected var remoteMaxAckDelay: Int = Settings.MAX_ACK_DELAY

    // The maximum amount of data that can be sent (to the peer) on the connection as a whole
    @Volatile
    private var maxDataAllowed = 0L

    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2
    // "initial_max_stream_data_bidi_local (0x0005):  This parameter is an integer value specifying the initial flow control limit for
    //  locally-initiated bidirectional streams.
    @Volatile
    private var initialMaxStreamDataBidiLocal = 0L

    // "initial_max_stream_data_bidi_remote (0x0006):  This parameter is an integer value specifying the initial flow control limit for peer-
    //  initiated bidirectional streams. "
    @Volatile
    var initialMaxStreamDataBidiRemote: Long = 0L
        private set

    // "initial_max_stream_data_uni (0x0007):  This parameter is an integer value specifying the initial flow control limit for unidirectional
    //  streams."
    @Volatile
    private var initialMaxStreamDataUni = 0L

    @Volatile
    private var slowStartThreshold = Long.MAX_VALUE

    @Volatile
    private var congestionRecoveryStartTime: TimeSource.Monotonic.ValueTimeMark? = null


    init {
        for (level in Level.levels()) {
            sendRequestQueues[level.ordinal] = SendRequestQueue()
        }

        for (level in Level.levels()) {
            ackGenerators[level.ordinal] = AckGenerator()
        }

        discardedLevels[Level.Initial.ordinal] = false
        discardedLevels[Level.Handshake.ordinal] = false
        discardedLevels[Level.App.ordinal] = false


        for (level in Level.levels()) {
            val levelIndex = level.ordinal
            packetAssemblers[levelIndex] = PacketAssembler(
                version, level,
                sendRequestQueues[levelIndex]!!, ackGenerators[levelIndex]!!
            )
        }

        for (level in Level.levels()) {
            lossDetectors[level.ordinal] = LossDetector(this)
        }
    }

    protected fun initializeCryptoStreams(tlsEngine: TlsEngine) {
        for (level in Level.levels()) {
            cryptoStreams[level.ordinal] = CryptoStream(
                version, level,
                tlsEngine, sendRequestQueues[level.ordinal]!!
            )
        }
    }

    internal fun ackGenerator(level: Level): AckGenerator {
        return ackGenerators[level.ordinal]!!
    }

    internal fun sendRequestQueue(level: Level): SendRequestQueue {
        return sendRequestQueues[level.ordinal]!!
    }

    internal fun packetAssembler(level: Level): PacketAssembler {
        return packetAssemblers[level.ordinal]!!
    }

    internal fun packetSent(
        packet: Packet,
        size: Int,
        timeSent: TimeSource.Monotonic.ValueTimeMark
    ) {
        if (isInflightPacket(packet)) {
            val packetStatus = PacketStatus(packet, size, timeSent)
            registerInFlight(packetStatus)
            lossDetectors[packet.level().ordinal]!!.packetSent(packetStatus)
        }
    }

    internal suspend fun insertRequest(level: Level, frame: Frame) {
        sendRequestQueue(level).insertRequest(frame)
    }

    internal suspend fun addRequest(level: Level, frame: Frame) {
        sendRequestQueue(level).appendRequest(frame)
    }

    internal fun process(ackFrame: FrameReceived.AckFrame, level: Level) {
        ackGenerator(level).ackFrameReceived(ackFrame)

        lossDetectors[level.ordinal]!!.processAckFrameReceived(ackFrame)
    }

    /**
     * Stop sending packets, but don't shutdown yet, so connection close can be sent.
     */
    suspend fun clearRequests() {
        // Stop sending packets, so discard any packet waiting to be send.
        for (queue in sendRequestQueues) {
            queue!!.clear()
        }

        // No more retransmissions either.
        stopRecovery()
    }

    open suspend fun cleanup() {
        for (level in Level.levels()) {
            discard(level)
        }
        discardKeys()

        for (level in Level.levels()) {
            cryptoStreams[level.ordinal]!!.cleanup()
        }
    }

    internal fun getCryptoStream(level: Level): CryptoStream {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.6
        // "There is a separate flow of cryptographic handshake data in each encryption level"
        return cryptoStreams[level.ordinal]!!
    }

    internal fun isDiscarded(level: Level): Boolean {
        return discardedLevels[level.ordinal]!!
    }

    internal suspend fun discard(level: Level) {
        discardedLevels[level.ordinal] = true

        // clear all send requests and probes on that level
        sendRequestQueues[level.ordinal]!!.clear()

        // 5.5.  Discarding Keys and Packet State
        //
        //   When packet protection keys are discarded (see Section 4.9 of
        //   [QUIC-TLS]), all packets that were sent with those keys can no longer
        //   be acknowledged because their acknowledgements cannot be processed
        //   anymore.  The sender MUST discard all recovery state associated with
        //   those packets and MUST remove them from the count of bytes in flight.
        lossDetectors[level.ordinal]!!.stop()


        // deactivate ack generator for level
        ackGenerator(level).cleanup()
    }

    val pto: Int
        get() = getSmoothedRtt() + 4 * getRttVar() + remoteMaxAckDelay


    fun init(
        initialMaxData: Long, initialMaxStreamDataBidiLocal: Long,
        initialMaxStreamDataBidiRemote: Long, initialMaxStreamDataUni: Long
    ) {
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote
        this.initialMaxStreamDataUni = initialMaxStreamDataUni
        this.maxDataAllowed = initialMaxData
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun addMaxDataAssigned(proposedStreamIncrement: Long) {
        maxDataAssigned.fetchAndAdd(proposedStreamIncrement)
    }

    fun determineInitialMaxStreamData(stream: Stream): Long {
        return if (stream.isUnidirectional) {
            initialMaxStreamDataUni
        } else if (stream.isClientInitiatedBidirectional) {
            // For the receiver (imposing the limit) the stream is peer-initiated (remote).
            // "This limit applies to newly created bidirectional streams opened by the endpoint that receives
            // the transport parameter."
            initialMaxStreamDataBidiRemote
        } else if (stream.isServerInitiatedBidirectional) {
            // For the receiver (imposing the limit), the stream is locally-initiated
            // "This limit applies to newly created bidirectional streams opened by the endpoint that sends the
            // transport parameter."
            initialMaxStreamDataBidiLocal
        } else {
            throw IllegalStateException()
        }
    }

    fun maxDataAllowed(value: Long) {
        maxDataAllowed = value
    }

    /**
     * Returns the current connection flow control limit.
     *
     * @return current connection flow control limit
     */
    fun maxDataAllowed(): Long {
        return maxDataAllowed
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun maxDataAssigned(): Long {
        return maxDataAssigned.load()
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun addSample(timeSent: TimeSource.Monotonic.ValueTimeMark, ackDelay: Int) {
        var delay = ackDelay


        if (delay > remoteMaxAckDelay) {
            delay = remoteMaxAckDelay
        }


        var rttSample = timeSent.elapsedNow().inWholeMilliseconds.toInt()
        if (rttSample < minRtt.load()) minRtt.store(rttSample)
        // Adjust for ack delay if it's plausible. Because times are truncated at millisecond precision,
        // consider rtt equal to min as plausible.
        if (rttSample >= minRtt.load() + delay) {
            rttSample -= delay
        }
        latestRtt.store(rttSample)

        if (smoothedRtt.load() == Settings.NOT_DEFINED) {
            // First time
            smoothedRtt.store(rttSample)
            rttVar.store(rttSample / 2)
        } else {
            val currentRttVar = abs(smoothedRtt.load() - rttSample)

            rttVar.store(
                // Add 2 to round to nearest integer
                (3 * rttVar.load() + currentRttVar + 2) / 4
            )

            smoothedRtt.store(
                // Add 4 to round to nearest integer
                (7 * smoothedRtt.load() + rttSample + 4) / 8
            )
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun getSmoothedRtt(): Int {
        val value = smoothedRtt.load()
        return if (value == Settings.NOT_DEFINED) {
            Settings.INITIAL_RTT
        } else {
            value
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun getRttVar(): Int {
        // Rtt-var is only used for computing PTO.
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-5.3
        // "The initial probe timeout for a new connection or new path SHOULD be set to twice the initial RTT"
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-5.2.1
        // "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay"
        // Hence, using an initial rtt-var of initial-rtt / 4, will result in an initial PTO of twice the initial RTT.
        // After the first packet is received, the rttVar will be computed from the real RTT sample.
        val value = rttVar.load()
        return if (value == Settings.NOT_DEFINED) {
            Settings.INITIAL_RTT / 4
        } else {
            value
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun getLatestRtt(): Int {
        return latestRtt.load()
    }

    // the packet status is a packet send earlier and has now been acknowlegded
    @OptIn(ExperimentalAtomicApi::class)
    internal fun processAckedPacket(acknowlegdedPacket: PacketStatus) {

        bytesInFlight.store(
            max((bytesInFlight.load() - acknowlegdedPacket.size.toLong()), 0)
        )


        // https://datatracker.ietf.org/doc/html/rfc9002#name-underutilizing-the-congesti
        // 7.8. Underutilizing the Congestion Window
        // When bytes in flight is smaller than the congestion window and sending is not pacing
        // limited, the congestion window is underutilized. This can happen due to insufficient
        // application data or flow control limits. When this occurs, the congestion window
        // SHOULD NOT be increased in either slow start or congestion avoidance.
        //
        val underutilizingCongestionWindow = bytesInFlight.load() < congestionWindow.load()
        if (!underutilizingCongestionWindow) {
            // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-6.4
            // "QUIC defines the end of recovery as a packet sent after the start
            // of recovery being acknowledged"
            if (congestionRecoveryStartTime == null ||
                acknowlegdedPacket.timeSent > congestionRecoveryStartTime!!
            ) {
                val operand = congestionWindow.load()
                congestionWindow.store(
                    if (operand < slowStartThreshold) {
                        // i.e. mode is slow start
                        operand + acknowlegdedPacket.size // ok
                    } else {
                        // i.e. mode is congestion avoidance
                        // A sender in congestion avoidance uses an Additive Increase Multiplicative
                        // Decrease (AIMD) approach that MUST limit the increase to the congestion window to
                        // at most one maximum datagram size for each congestion window that is acknowledged.
                        operand + (Settings.MAX_DATAGRAM_SIZE.toLong() * acknowlegdedPacket.size / operand)
                    }
                )
            }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun discardBytesInFlight(packetStatus: PacketStatus) {

        bytesInFlight.store(
            max((bytesInFlight.load() - packetStatus.size.toLong()), 0)
        )
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun registerLost(packetStatus: PacketStatus) {
        discardBytesInFlight(packetStatus)


        // 6.4.  Recovery Period
        //
        //   Recovery is a period of time beginning with detection of a lost
        //   packet or an increase in the ECN-CE counter.  Because QUIC does not
        //   retransmit packets, it defines the end of recovery as a packet sent
        //   after the start of recovery being acknowledged.  This is slightly
        //   different from TCP's definition of recovery, which ends when the lost
        //   packet that started recovery is acknowledged.
        //
        //   The recovery period limits congestion window reduction to once per
        //   round trip.  During recovery, the congestion window remains unchanged
        //   irrespective of new losses or increases in the ECN-CE counter.
        if (congestionRecoveryStartTime == null ||
            packetStatus.timeSent > congestionRecoveryStartTime!!
        ) {
            congestionRecoveryStartTime = TimeSource.Monotonic.markNow()

            //   When a loss is detected,
            //   NewReno halves the congestion window and sets the slow start
            //   threshold  to the new congestion window.
            val operand = congestionWindow.load()


            // When a loss is detected,
            // NewReno halves the congestion window and sets the slow start
            // threshold to the new congestion window.
            slowStartThreshold = operand / Settings.CONGESTION_LOSS_REDUCTION_FACTOR
            if (slowStartThreshold < Settings.MINIMUM_CONGESTION_WINDOW) {
                Settings.MINIMUM_CONGESTION_WINDOW.toLong()
            } else {
                slowStartThreshold
            }

            congestionWindow.store(slowStartThreshold)
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun remainingCwnd(): Long {
        return max((congestionWindow.load() - bytesInFlight.load()), 0)
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun registerInFlight(packetStatus: PacketStatus) {
        bytesInFlight.addAndFetch(packetStatus.size.toLong())
    }

    suspend fun lossDetection() {
        for (level in Level.levels()) {
            lossDetectors[level.ordinal]!!.detectLostPackets()
        }
    }

    private fun stopRecovery() {
        for (lossDetector in lossDetectors) {
            lossDetector!!.stop()
        }
    }
}
