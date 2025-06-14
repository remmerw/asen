package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

internal object PacketService {

    fun createInitial(
        version: Int, frames: List<Frame>, packetNumber: Long,
        scid: Number, dcid: Number
    ): Packet.InitialPacket {
        return Packet.InitialPacket(
            version, dcid, scid,
            frames, packetNumber, null
        )
    }

    /**
     * Constructs a short header packet for sending (client role).
     */
    fun createShortHeader(
        version: Int, frames: List<Frame>,
        packetNumber: Long, dcid: Number
    ): Packet.ShortHeaderPacket {
        return Packet.ShortHeaderPacket(version, dcid, frames, packetNumber)
    }

    fun createHandshake(
        version: Int, frames: List<Frame>,
        packetNumber: Long, scid: Number, dcid: Number
    ): Packet.HandshakePacket {
        return Packet.HandshakePacket(version, dcid, scid, frames, packetNumber)
    }


    fun protectPacketNumberAndPayload(
        additionalData: ByteArray,
        packetNumberSize: Int, payload: ByteArray,
        clientSecrets: Keys, packetNumber: Long
    ): Buffer {
        val packetNumberPosition = additionalData.size - packetNumberSize

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The associated data, A, for the AEAD is the contents of the QUIC
        // header, starting from the flags octet in either the short or long
        // header, up to and including the unprotected packet number."
        val encryptedPayload = encryptPayload(
            payload, additionalData, packetNumber, clientSecrets
        )

        val encodedPacketNumber = encodePacketNumber(packetNumber)
        val mask = createHeaderProtectionMask(
            encryptedPayload,
            encodedPacketNumber.size, clientSecrets
        )

        for (i in encodedPacketNumber.indices) {
            additionalData[i + packetNumberPosition] =
                (encodedPacketNumber[i].toInt() xor mask[1 + i].toInt()).toByte()
        }

        var flags = additionalData[0]
        flags = if ((flags.toInt() and 0x80) == 0x80) {
            // Long header: 4 bits masked
            (flags.toInt() xor (mask[0].toInt() and 0x0f).toByte().toInt()).toByte()
        } else {
            // Short header: 5 bits masked
            (flags.toInt() xor (mask[0].toInt() and 0x1f).toByte().toInt()).toByte()
        }
        additionalData[0] = flags

        val buffer = Buffer()
        buffer.write(additionalData)
        buffer.write(encryptedPayload)

        return buffer
    }

    fun encodePacketNumber(packetNumber: Long): ByteArray {
        return if (packetNumber <= 0xff) {
            byteArrayOf(packetNumber.toByte())
        } else if (packetNumber <= 0xffff) {
            byteArrayOf(
                (packetNumber shr 8).toByte(),
                (packetNumber and 0x00ffL).toByte()
            )
        } else if (packetNumber <= 0xffffff) {
            byteArrayOf(
                (packetNumber shr 16).toByte(), (packetNumber shr 8).toByte(),
                (packetNumber and 0x00ffL).toByte()
            )
        } else if (packetNumber <= 0xffffffffL) {
            byteArrayOf(
                (packetNumber shr 24).toByte(), (packetNumber shr 16).toByte(),
                (packetNumber shr 8).toByte(), (packetNumber and 0x00ffL).toByte()
            )
        } else {
            throw IllegalStateException(" not yet implemented cannot encode pn > 4 bytes")
        }
    }


    fun createHeaderProtectionMask(
        ciphertext: ByteArray,
        encodedPacketNumberLength: Int,
        secrets: Keys
    ): ByteArray {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        val sampleOffset = 4 - encodedPacketNumberLength
        val sample = ciphertext.copyOfRange(sampleOffset, sampleOffset + 16)

        return secrets.createHeaderProtectionMask(sample)
    }

    private fun encryptPayload(
        input: ByteArray, associatedData: ByteArray,
        packetNumber: Long, secrets: Keys
    ): ByteArray {
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"

        val writeIV = secrets.writeIV
        val nonceInput = Buffer()

        repeat(writeIV.size - Long.SIZE_BYTES) {
            nonceInput.writeByte(0x00.toByte())
        }

        nonceInput.writeLong(packetNumber)
        require(nonceInput.size == writeIV.size.toLong())
        val nia = nonceInput.readByteArray()

        val nonce = ByteArray(12)
        var i = 0
        for (b in nia) nonce[i] = (b.toInt() xor writeIV[i++].toInt()).toByte()

        return secrets.aeadEncrypt(associatedData, nonce, input)
    }

    /**
     * Updates the given flags byte to encode the packet number length that is used for
     * encoding the given packet number.
     */
    fun encodePacketNumberLength(flags: Byte, packetNumber: Long): Byte {
        return if (packetNumber <= 0xff) {
            flags
        } else if (packetNumber <= 0xffff) {
            (flags.toInt() or 0x01).toByte()
        } else if (packetNumber <= 0xffffff) {
            (flags.toInt() or 0x02).toByte()
        } else if (packetNumber <= 0xffffffffL) {
            (flags.toInt() or 0x03).toByte()
        } else {
            throw IllegalStateException("not yet implemented cannot encode pn > 4 bytes")
        }
    }

    fun generatePayloadBytes(frames: List<Frame>, encodedPacketNumberLength: Int): ByteArray {

        Buffer().use { buffer ->
            for ((_, frameBytes) in frames) {
                buffer.write(frameBytes)
            }
            val serializeFramesLength = buffer.size

            // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
            // "To ensure that sufficient data is available for sampling, packets are
            // padded so that the combined lengths of the encoded packet number and
            // protected payload is at least 4 bytes longer than the sample required
            // for header protection."
            if (encodedPacketNumberLength + serializeFramesLength < 4) {
                val length = 4 - encodedPacketNumberLength - serializeFramesLength
                buffer.write(ByteArray(length.toInt()))
            }
            val data = buffer.readByteArray()
            require(data.size < Settings.MAX_PACKET_SIZE) { "Invalid packet size" }
            return data
        }

    }

}
