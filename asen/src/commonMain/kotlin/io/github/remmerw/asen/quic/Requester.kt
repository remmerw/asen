package io.github.remmerw.asen.quic


interface Requester {
    suspend fun data(stream: Stream, data: ByteArray)

    fun done()
}
