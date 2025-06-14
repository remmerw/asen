package io.github.remmerw.asen.quic

import kotlin.time.TimeSource


internal data class PacketStatus(
    val packet: Packet, val size: Int,
    val timeSent: TimeSource.Monotonic.ValueTimeMark
)

