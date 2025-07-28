package io.github.remmerw.asen.quic


interface Requester {
    fun data(stream: Stream, data: ByteArray)

    fun done()
}
