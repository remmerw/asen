package io.github.remmerw.asen.quic


internal data class PacketHeader(
    val level: Level, val version: Int, val dcid: Number, val scid: Int?,
    val framesBytes: ByteArray, val packetNumber: Long, val updated: Keys?
) {
    fun hasUpdatedKeys(): Boolean {
        return updated != null
    }


    override fun hashCode(): Int {
        var result = level.hashCode()
        result = 31 * result + version
        result = 31 * result + dcid.hashCode()
        result = 31 * result + (scid ?: 0)
        result = 31 * result + framesBytes.contentHashCode()
        result = 31 * result + packetNumber.hashCode()
        result = 31 * result + (updated?.hashCode() ?: 0)
        return result
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PacketHeader

        if (version != other.version) return false
        if (scid != other.scid) return false
        if (packetNumber != other.packetNumber) return false
        if (level != other.level) return false
        if (dcid != other.dcid) return false
        if (!framesBytes.contentEquals(other.framesBytes)) return false
        if (updated != other.updated) return false

        return true
    }
}
