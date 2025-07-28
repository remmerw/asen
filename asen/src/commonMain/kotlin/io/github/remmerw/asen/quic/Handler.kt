package io.github.remmerw.asen.quic

// Note: a protocol handler is only invoked, when a remote peer initiate a
// stream over an existing connection
interface Handler {

    // is invoked, when the your protocol is requested
    fun protocol(stream: Stream)

    fun data(stream: Stream, data: ByteArray)

}