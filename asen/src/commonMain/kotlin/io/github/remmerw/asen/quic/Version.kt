package io.github.remmerw.asen.quic


internal object Version {
    fun toBytes(versionId: Int): ByteArray {
        return numToBytes(versionId)
    }

    fun isV2(versionId: Int): Boolean {
        return versionId == V2
    }

    const val V1: Int = 0x00000001
    const val V2: Int = 0x709a50c4

}
