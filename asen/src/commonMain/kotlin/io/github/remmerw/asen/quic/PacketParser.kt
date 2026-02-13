package io.github.remmerw.asen.quic

import io.github.remmerw.asen.debug
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.math.max
import kotlin.math.min


internal object PacketParser {

    private fun getInitialPacketType(version: Int): Byte {
        return if (Version.isV2(version)) {
            Settings.INITIAL_V2_TYPE.toByte()
        } else {
            Settings.INITIAL_V1_TYPE.toByte()
        }
    }

    private fun checkInitialPacketType(version: Int, type: Int) {
        check(type == getInitialPacketType(version).toInt())
    }


    private fun parseToken(buffer: Reader) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
        // "An Initial packet (shown in Figure 13) has two additional header
        // fields that are added to the Long Header before the Length field."

        val tokenLength = parseLong(buffer)

        if (tokenLength > 0) {
            if (tokenLength <= buffer.remaining()) {
                // val token = buffer.getByteArray(tokenLength.toInt())
                buffer.skip(tokenLength.toInt())
            } else {
                error("invalid packet length")
            }
        }
    }

    fun invalidFixBit(flags: Byte): Boolean {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.2
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.3
        // "Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
        // containing a zero value for this bit are not valid packets in this
        // version and MUST be discarded."
        return (flags.toInt() and 0x40) != 0x40
    }

    fun parseLevel(reader: Reader, flags: Byte, version: Int): Level? {
        if ((flags.toInt() and 0x80) == 0x80) {
            // Long header packet
            return parseLongHeaderLevel(reader, flags, version)
        } else {
            // Short header packet
            if ((flags.toInt() and 0xc0) == 0x40) {
                return Level.App
            }
        }
        return null
    }

    private fun parseLongHeaderLevel(reader: Reader, flags: Byte, version: Int): Level? {
        if (reader.remaining() < 4) { // 4 bits required here
            return null
        }

        val versionId = reader.getInt() // 4 bits

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (versionId == 0) {
            return null
        }

        if (versionId != version) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
            // "... packets are discarded if they indicate a different protocol version than that of the connection..."
            return null
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.5
        // "An Initial packet uses long headers with a payloadType value of 0x0."
        if ((flags.toInt() and 0xf0) == 0xc0) {  // 1100 0000
            return Level.Initial
        } else if ((flags.toInt() and 0xf0) == 0xf0) {  // 1111 0000
            // Retry packet....
            debug("Retry packet is intentionally not supported")
            return null
        } else if ((flags.toInt() and 0xf0) == 0xe0) {  // 1110 0000
            return Level.Handshake
        } else if ((flags.toInt() and 0xf0) == 0xd0) {  // 1101 0000
            // 0-RTT Protected
            // "It is used to carry "early"
            // data from the client to the server as part of the first flight, prior
            // to handshake completion."

            // When such a packet arrives, consider it to be caused by network corruption, so

            debug("network corruption detected")
            return null
        } else {
            debug("Should not happen, all cases should be covered above")
            return null
        }
    }

    private fun scid(buffer: Reader): Int? {
        val srcConnIdLength = buffer.getByte().toInt()
        if (srcConnIdLength != Int.SIZE_BYTES) {
            return null
        }
        if (buffer.remaining() < srcConnIdLength) {
            return null
        }
        return buffer.getInt()
    }

    fun parseInitialPacketHeader(
        reader: Reader,
        dcid: Number,
        flags: Byte,
        posFlags: Int,
        version: Int,
        keys: Keys,
        largestPacketNumber: Long
    ): PacketHeader? {
        checkInitialPacketType(version, (flags.toInt() and 0x30) shr 4)

        val scid = scid(reader) ?: return null

        parseToken(reader) // token not used yet

        // "The length of the remainder of the packet (that is, the Packet Number and
        // Payload fields) in bytes"
        val length = parseInt(reader)

        return parsePacketNumberAndPayload(
            reader,
            Level.Initial, version, flags, posFlags,
            length, keys, largestPacketNumber, dcid, scid
        )
    }


    fun parseShortPacketHeader(
        reader: Reader, dcid: Number, flags: Byte,
        posFlags: Int, version: Int, keys: Keys,
        largestPacketNumber: Long
    ): PacketHeader? {
        return parsePacketNumberAndPayload(
            reader,
            Level.App, version, flags, posFlags,
            reader.remaining(), keys,
            largestPacketNumber, dcid, null
        )
    }


    private fun getHandshakePacketType(version: Int): Byte {
        return if (Version.isV2(version)) {
            Settings.HANDSHAKE_V2_TYPE.toByte()
        } else {
            Settings.HANDSHAKE_V1_TYPE.toByte()
        }
    }

    private fun checkHandshakePacketType(version: Int, type: Int) {
        check(type == getHandshakePacketType(version).toInt()) {
            "Programming error: this method shouldn't " +
                    "have been called if packet is not Initial"
        }
    }

    fun dcid(reader: Reader, level: Level): Number? {
        when (level) {
            Level.App -> {
                if (reader.remaining() < Int.SIZE_BYTES) {
                    return null
                }
                return reader.getInt()
            }

            Level.Initial, Level.Handshake -> {
                val dstConnIdLength = reader.getByte().toInt()
                // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.2
                // "In QUIC version 1, this value MUST NOT exceed 20.  Endpoints that receive a version 1
                // long header with a value larger than 20 MUST drop the packet."
                if (dstConnIdLength !in 0..20) {
                    return null
                }
                if (reader.remaining() < dstConnIdLength) {
                    return null
                }
                if (dstConnIdLength == Int.SIZE_BYTES) {
                    return reader.getInt()
                }
                if (dstConnIdLength == Long.SIZE_BYTES) {
                    return reader.getLong()
                }
                return null
            }
        }
    }

    fun parseHandshakePackageHeader(
        reader: Reader,
        dcid: Number,
        flags: Byte,
        posFlags: Int,
        version: Int,
        keys: Keys,
        largestPacketNumber: Long
    ): PacketHeader? {
        checkHandshakePacketType(version, (flags.toInt() and 0x30) shr 4)

        val scid = scid(reader) ?: return null

        // "The length of the remainder of the packet (that is, the Packet Number and Payload
        // fields) in bytes"
        val length = parseInt(reader)

        return parsePacketNumberAndPayload(
            reader,
            Level.Handshake, version, flags, posFlags,
            length, keys, largestPacketNumber, dcid, scid
        )
    }


    fun frameHeader(buffer: Reader, posFlags: Int): ByteArray {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags byte in either the short or long
        //   header, up to and including the unprotected packet number."
        val currentPosition = buffer.position()
        buffer.position(posFlags)
        val frameHeader = buffer.getByteArray(currentPosition - posFlags)
        buffer.position(currentPosition)
        return frameHeader
    }

    private fun parsePacketNumberAndPayload(
        reader: Reader,
        level: Level,
        version: Int,
        flags: Byte, posFlags: Int,
        remainingLength: Int,
        keys: Keys,
        largestPacketNumber: Long,
        dcid: Number, scid: Int?
    ): PacketHeader? {
        var secrets = keys
        if (reader.remaining() < remainingLength) {
            return null
        }

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "When removing packet protection, an endpoint
        // first removes the header protection."
        val startPos = reader.position()

        try {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
            // "The same number of bytes are always sampled, but an allowance needs
            // to be made for the endpoint removing protection, which will not know
            // the length of the Packet Number field. In sampling the packet
            // ciphertext, the Packet Number field is assumed to be 4 bytes long
            // (its maximum possible encoded length)."
            if (reader.remaining() < 4) {
                return null
            }
            reader.position(startPos + 4)

            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
            // "This algorithm samples 16 bytes from the packet ciphertext."
            if (reader.remaining() < 16) {
                return null
            }
            val sample = reader.getByteArray(16)


            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
            // "Header protection is applied after packet protection is applied (see
            // Section 5.3).  The ciphertext of the packet is sampled and used as
            // input to an encryption algorithm."
            val mask = createHeaderProtectionMask(sample, secrets)


            // "The output of this algorithm is a 5 byte mask which is applied to the
            // protected header fields using exclusive OR.  The least significant
            // bits of the first byte of the packet are masked by the least
            // significant bits of the first mask byte
            val decryptedFlags = if ((flags.toInt() and 0x80) == 0x80) {
                // Long header: 4 bits masked
                (flags.toInt() xor (mask[0].toInt() and 0x0f)).toByte()
            } else {
                // Short header: 5 bits masked
                (flags.toInt() xor (mask[0].toInt() and 0x1f)).toByte()
            }


            var updated: Keys? = null
            if (level == Level.App) {
                val keyPhaseBit = ((decryptedFlags.toInt() and 0x04) shr 2).toShort()
                if (secrets.checkKeyPhase(keyPhaseBit)) {
                    secrets = Keys.computeKeyUpdate(version, secrets)
                    updated = secrets
                }
            }

            reader.position(startPos)


            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
            // "pn_length = (packet[0] & 0x03) + 1"
            val protectedPackageNumberLength = (decryptedFlags.toInt() and 0x03) + 1

            val protectedPackageNumber = reader.getByteArray(protectedPackageNumberLength)

            val unprotectedPacketNumber = ByteArray(protectedPackageNumberLength)
            for (i in 0 until protectedPackageNumberLength) {
                // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
                // " ...and the packet number is
                // masked with the remaining bytes.  Any unused bytes of mask that might
                // result from a shorter packet number encoding are unused."
                unprotectedPacketNumber[i] =
                    (protectedPackageNumber[i].toInt() xor mask[1 + i].toInt()).toByte()
            }
            var packetNumber =
                bytesToInt(unprotectedPacketNumber).toLong()

            packetNumber = decodePacketNumber(
                packetNumber, largestPacketNumber,
                protectedPackageNumberLength * 8
            )

            // validate the packet number (minAllowed)
            val minAllowedPacketNumber = max(
                (largestPacketNumber - Settings.PACKET_NUMBER_OFFSET),
                0
            )
            if (packetNumber < minAllowedPacketNumber) {
                return null // can happen when decoding failed
            }
            // this is not according to spec [but it is required here]
            val maxAllowedPacketNumber: Long = min(
                (largestPacketNumber + Settings.PACKET_NUMBER_OFFSET),
                Long.MAX_VALUE
            )
            if (packetNumber > maxAllowedPacketNumber) {
                return null // can happen when decoding failed
            }


            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
            // "The associated data, A, for the AEAD is the contents of the QUIC
            //   header, starting from the flags byte in either the short or long
            //   header, up to and including the unprotected packet number."
            val frameHeader = frameHeader(reader, posFlags)
            frameHeader[0] = decryptedFlags


            // Copy unprotected (decrypted) packet number in frame header, before decrypting payload.
            unprotectedPacketNumber.copyInto(
                frameHeader, frameHeader.size -
                        (protectedPackageNumberLength), 0, protectedPackageNumberLength
            )

            // "The input plaintext, P, for the AEAD is the payload of the QUIC
            // packet, as described in [QUIC-TRANSPORT]."
            // "The output ciphertext, C, of the AEAD is transmitted in place of P."
            val encryptedPayloadLength = remainingLength - protectedPackageNumberLength
            if (encryptedPayloadLength < 1) {
                return null
            }

            val ciphertext = reader.getByteArray(encryptedPayloadLength)


            val frameBytes = decryptPayload(
                ciphertext, frameHeader, packetNumber, secrets
            )

            return PacketHeader(level, version, dcid, scid, frameBytes, packetNumber, updated)
        } catch (throwable: Throwable) {
            debug(throwable)
            throw throwable
        } finally {
            reader.position(startPos + remainingLength) // prepare for next iteration
        }
    }

    private fun createHeaderProtectionMask(sample: ByteArray, secrets: Keys): ByteArray {
        return PacketService.createHeaderProtectionMask(sample, 4, secrets)
    }


    private fun decodePacketNumber(
        truncatedPacketNumber: Long,
        largestPacketNumber: Long,
        bits: Int
    ): Long {
        // https://www.rfc-editor.org/rfc/rfc9000.html#sample-packet-number-decoding
        // "Figure 47: Sample Packet Number Decoding Algorithm"
        val expectedPacketNumber = largestPacketNumber + 1
        val pnWindow = 1L shl bits
        val pnHalfWindow = pnWindow / 2
        val pnMask = -pnWindow

        val candidatePn = (expectedPacketNumber and pnMask) or truncatedPacketNumber
        if (candidatePn <= expectedPacketNumber - pnHalfWindow && candidatePn < (1L shl 62) - pnWindow) {
            return candidatePn + pnWindow
        }
        if (candidatePn > expectedPacketNumber + pnHalfWindow && candidatePn >= pnWindow) {
            return candidatePn - pnWindow
        }

        return candidatePn
    }

    fun decryptPayload(
        ciphertext: ByteArray, associatedData: ByteArray,
        packetNumber: Long, secrets: Keys
    ): ByteArray {
        val nonceInput = Buffer()
        nonceInput.writeInt(0)
        nonceInput.writeLong(packetNumber)

        val writeIV = secrets.writeIV
        val iv = ByteArray(12)
        var i = 0
        for (b in nonceInput.readByteArray()) {
            iv[i] = (b.toInt() xor writeIV[i++].toInt()).toByte()
        }

        return secrets.aeadDecrypt(associatedData, iv, ciphertext)
    }


}
