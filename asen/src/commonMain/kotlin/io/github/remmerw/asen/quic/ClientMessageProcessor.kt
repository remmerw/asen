package io.github.remmerw.asen.quic


internal interface ClientMessageProcessor : MessageProcessor {

    override fun received(clientHello: ClientHello) {
        throw UnexpectedMessageAlert("no client hello expected $clientHello")
    }
}
