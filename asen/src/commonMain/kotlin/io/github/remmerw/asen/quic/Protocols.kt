package io.github.remmerw.asen.quic

class Protocols {
    private val protocols: MutableMap<String, Handler> = mutableMapOf()
    fun names(): Set<String> {
        return protocols.keys.toSet()
    }

    fun put(key: String, handler: Handler) {
        protocols[key] = handler
    }

    fun get(key: String): Handler? {
        return protocols[key]
    }
}