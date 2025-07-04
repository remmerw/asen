package io.github.remmerw.asen
import io.ktor.network.sockets.InetSocketAddress
import java.net.InetAddress

actual fun createInetSocketAddress(address: ByteArray, port:Int) : InetSocketAddress {
    if(address.size == 16) {
        val inet = InetAddress.getByAddress(address)
        return InetSocketAddress(inet.hostName, port)
    } else {
        val host = io.github.remmerw.asen.core.hostname(address)
        return InetSocketAddress(host, port)
    }
}