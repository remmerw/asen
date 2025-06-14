package io.github.remmerw.asen.quic


/**
 * Base class for all classes that represent a QUIC frame.
 * [...](https://www.rfc-editor.org/rfc/rfc9000.html#frames)
 */
internal data class Frame(val frameType: FrameType, val frameBytes: ByteArray) {
    fun frameLength(): Int {
        return frameBytes.size
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Frame

        if (frameType != other.frameType) return false
        if (!frameBytes.contentEquals(other.frameBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = frameType.hashCode()
        result = 31 * result + frameBytes.contentHashCode()
        return result
    }


}
