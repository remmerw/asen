package io.github.remmerw.asen
import io.ktor.network.sockets.InetSocketAddress

actual fun createInetSocketAddress(address: ByteArray, port:Int) : InetSocketAddress {
    val host = io.github.remmerw.asen.core.hostname(address) // has to be tested if it is working
    return InetSocketAddress(host, port)
}