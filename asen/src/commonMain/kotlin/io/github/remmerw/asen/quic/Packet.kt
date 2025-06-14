package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

val UNDEFINED_TOKEN: ByteArray = byteArrayOf(0x00.toByte())

internal interface Packet {
    fun packetNumber(): Long

    fun level(): Level

    fun frames(): List<Frame>

    /**
     * Estimates what the length of this packet will be after it has been encrypted.
     * The returned length must be less then or equal the actual length after encryption.
     * Length estimates are used when preparing packets for sending, where certain limits must
     * be met (e.g. congestion control, max datagram size, ...).
     */
    fun estimateLength(): Int

    fun framesLength(): Int {
        var sum = 0
        for (frame in frames()) {
            sum += frame.frameLength()
        }
        return sum
    }

    fun generatePacketBytes(keys: Keys): Buffer

    val isAckOnly: Boolean
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
        get() {
            for ((frameType) in frames()) {
                if (frameType != FrameType.AckFrame) {
                    return false
                }
            }
            return true
        }


    data class HandshakePacket(
        val version: Int, val dcid: Number, val scid: Number,
        val frames: List<Frame>, val packetNumber: Long
    ) : Packet {
        private val packetType: Byte
            get() = if (Version.isV2(version)) {
                Settings.HANDSHAKE_V2_TYPE.toByte()
            } else {
                Settings.HANDSHAKE_V1_TYPE.toByte()
            }


        override fun generatePacketBytes(keys: Keys): Buffer {
            val frameHeader = generateFrameHeaderInvariant()
            val encodedPacketNumber = PacketService.encodePacketNumber(packetNumber)
            val frameBytes = PacketService.generatePayloadBytes(frames, encodedPacketNumber.size)


            val packetLength = frameBytes.size + 16 + encodedPacketNumber.size // 16 is what


            // encryption adds, note that final length is larger due to adding packet length
            val encPacketLength = bytesNeeded(packetLength.toLong())

            val capacity = frameHeader.size + encodedPacketNumber.size + encPacketLength
            val additionalData = Buffer()
            additionalData.write(frameHeader)
            encode(packetLength, additionalData)
            additionalData.write(encodedPacketNumber)
            require(additionalData.size <= capacity)
            return PacketService.protectPacketNumberAndPayload(
                additionalData.readByteArray(),
                encodedPacketNumber.size,
                frameBytes, keys, packetNumber
            )
        }

        override fun packetNumber(): Long {
            return packetNumber
        }

        override fun level(): Level {
            return Level.Handshake
        }

        override fun frames(): List<Frame> {
            return frames
        }

        override fun estimateLength(): Int {
            val payloadLength = framesLength()
            return (1
                    + 4
                    + 1 + lengthNumber(dcid)
                    + 1 + Int.SIZE_BYTES
                    + (if (payloadLength + 1 > 63) 2 else 1)
                    + 1 // packet number length: will usually be just 1, actual value cannot be
                    // computed until packet number is known
                    + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                    // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                    + 16)
        }

        private fun generateFrameHeaderInvariant(): ByteArray {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
            // "Long Header Packet {
            //    Header Form (1) = 1,
            //    Fixed Bit (1) = 1,
            //    Long Packet Type (2),
            //    Type-Specific Bits (4),"
            //    Version (32),
            //    Destination Connection ID Length (8),
            //    Destination Connection ID (0..160),
            //    Source Connection ID Length (8),
            //    Source Connection ID (0..160),
            //    Type-Specific Payload (..),
            //  }

            val dcidLength = lengthNumber(dcid)

            // Packet payloadType and packet number length
            val flags = PacketService.encodePacketNumberLength(
                (192 or
                        (packetType.toInt() shl 4)).toByte(), packetNumber
            )

            val version = Version.toBytes(version)
            val capacity = 1 + version.size + 1 + dcidLength +
                    1 + Int.SIZE_BYTES
            val buffer = Buffer()
            buffer.writeByte(flags)
            // Version
            buffer.write(version)
            // DCID Len
            buffer.writeByte(dcidLength.toByte())
            // Destination connection id
            if (dcid is Long) {
                buffer.writeLong(dcid)
            } else {
                buffer.writeInt(dcid.toInt())
            }
            // SCID Len
            buffer.writeByte(Int.SIZE_BYTES.toByte())
            // Source connection id
            buffer.writeInt(scid.toInt())
            require(buffer.size.toInt() == capacity)
            return buffer.readByteArray()
        }
    }


    @Suppress("ArrayInDataClass")
    data class InitialPacket(
        val version: Int, val dcid: Number, val scid: Number,
        val frames: List<Frame>, val packetNumber: Long, val token: ByteArray?
    ) :
        Packet {
        private val packetType: Byte
            get() {
                return if (Version.isV2(version)) {
                    Settings.INITIAL_V2_TYPE.toByte()
                } else {
                    Settings.INITIAL_V1_TYPE.toByte()
                }
            }

        private fun generateAdditionalFields(): ByteArray {
            // Token length (variable-length integer)
            if (token != null) {
                val length = bytesNeeded(token.size.toLong())
                val buffer = Buffer()
                encode(token.size, buffer)
                buffer.write(token)
                require(buffer.size <= length + token.size)
                return buffer.readByteArray()
            } else {
                return UNDEFINED_TOKEN
            }
        }

        private fun estimateAdditionalFieldsLength(): Int {
            return if (token == null) 1 else 1 + token.size
        }

        override fun generatePacketBytes(keys: Keys): Buffer {
            val frameHeader = generateFrameHeaderInvariant()
            val addFields = generateAdditionalFields()
            val encodedPacketNumber = PacketService.encodePacketNumber(packetNumber)
            val frameBytes = PacketService.generatePayloadBytes(frames, encodedPacketNumber.size)

            // 16 is what encryption adds, note that final length is larger due to adding packet length
            val packetLength = frameBytes.size + 16 + encodedPacketNumber.size

            val encPacketLength = bytesNeeded(packetLength.toLong())

            val capacity = frameHeader.size + addFields.size +
                    encPacketLength + encodedPacketNumber.size
            val additionalData = Buffer()
            additionalData.write(frameHeader)
            additionalData.write(addFields)
            encode(packetLength, additionalData)
            additionalData.write(encodedPacketNumber)
            require(additionalData.size <= capacity)

            return PacketService.protectPacketNumberAndPayload(
                additionalData.readByteArray(),
                encodedPacketNumber.size,
                frameBytes, keys, packetNumber
            )
        }

        override fun packetNumber(): Long {
            return packetNumber
        }

        override fun level(): Level {
            return Level.Initial
        }

        override fun frames(): List<Frame> {
            return frames
        }

        override fun estimateLength(): Int {
            val payloadLength = framesLength()
            return (1
                    + 4
                    + 1 + lengthNumber(dcid)
                    + 1 + Int.SIZE_BYTES
                    + estimateAdditionalFieldsLength()
                    + (if (payloadLength + 1 > 63) 2 else 1)
                    + 1 // packet number length: will usually be just 1, actual value cannot be computed until packet number is known
                    + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                    // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                    + 16)
        }

        private fun generateFrameHeaderInvariant(): ByteArray {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
            // "Long Header Packet {
            //    Header Form (1) = 1,
            //    Fixed Bit (1) = 1,
            //    Long Packet Type (2),
            //    Type-Specific Bits (4),"
            //    Version (32),
            //    Destination Connection ID Length (8),
            //    Destination Connection ID (0..160),
            //    Source Connection ID Length (8),
            //    Source Connection ID (0..160),
            //    Type-Specific Payload (..),
            //  }

            // Packet payloadType and packet number length

            val flags = PacketService.encodePacketNumberLength(
                (192 or
                        (packetType.toInt() shl 4)).toByte(), packetNumber
            )

            val dcidLength = lengthNumber(dcid)

            val version = Version.toBytes(version)
            val capacity = 1 + version.size + 1 + dcidLength +
                    1 + Int.SIZE_BYTES
            val buffer = Buffer()

            buffer.writeByte(flags)
            // Version
            buffer.write(version)
            // DCID Len
            buffer.writeByte(dcidLength.toByte())
            // Destination connection id
            if (dcid is Long) {
                buffer.writeLong(dcid)
            } else {
                buffer.writeInt(dcid.toInt())
            }
            // SCID Len
            buffer.writeByte(Int.SIZE_BYTES.toByte())
            // Source connection id
            buffer.writeInt(scid.toInt())
            require(buffer.size.toInt() == capacity)
            return buffer.readByteArray()
        }

    }


    data class ShortHeaderPacket(
        val version: Int, val dcid: Number, val frames: List<Frame>,
        val packetNumber: Long
    ) : Packet {
        override fun packetNumber(): Long {
            return packetNumber
        }

        override fun level(): Level {
            return Level.App
        }

        override fun frames(): List<Frame> {
            return frames
        }

        override fun estimateLength(): Int {
            val payloadLength = framesLength()
            return (1
                    + lengthNumber(dcid)
                    + 1 // packet number length: will usually be just 1, actual value cannot be
                    // computed until packet number is known
                    + payloadLength // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                    // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                    + 16)
        }

        override fun generatePacketBytes(keys: Keys): Buffer {
            val flags = getFlags(keys)

            val encodedPacketNumber = PacketService.encodePacketNumber(packetNumber)
            val dcidLength = lengthNumber(dcid)

            val capacity = 1 + dcidLength + encodedPacketNumber.size
            val additionalData = Buffer()
            additionalData.writeByte(flags)
            if (dcid is Long) {
                additionalData.writeLong(dcid)
            } else {
                additionalData.writeInt(dcid.toInt())
            }
            additionalData.write(encodedPacketNumber)

            val frameBytes = PacketService.generatePayloadBytes(
                frames, encodedPacketNumber.size
            )
            require(additionalData.size.toInt() == capacity)

            return PacketService.protectPacketNumberAndPayload(
                additionalData.readByteArray(),
                encodedPacketNumber.size, frameBytes,
                keys, packetNumber
            )
        }

        private fun getFlags(keys: Keys): Byte {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.3
            // "|0|1|S|R|R|K|P P|"
            // "Spin Bit (S):  The sixth bit (0x20) of byte 0 is the Latency Spin
            //      Bit, set as described in [SPIN]."
            // "Reserved Bits (R):  The next two bits (those with a mask of 0x18) of
            //      byte 0 are reserved. (...) The value included prior to protection MUST be set to 0. "
            var flags: Byte = 0x40 // 0100 0000
            val keyPhaseBit = keys.keyPhase
            flags = (flags.toInt() or (keyPhaseBit.toInt() shl 2)).toByte()
            flags = PacketService.encodePacketNumberLength(flags, packetNumber)
            return flags
        }
    }
}

// https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
// "Packets that contain ack-eliciting frames elicit an ACK from the receiver (...)
// and are called ack-eliciting packets."
internal fun isAckEliciting(packet: Packet): Boolean {
    for (frame in packet.frames()) {
        if (isAckEliciting(frame)) {
            return true
        }
    }
    return false
}

internal fun isInflightPacket(packet: Packet): Boolean {
    for (frame in packet.frames()) {
        if (isAckEliciting(frame) || frame.frameType == FrameType.PaddingFrame) {
            return true
        }
    }
    return false
}