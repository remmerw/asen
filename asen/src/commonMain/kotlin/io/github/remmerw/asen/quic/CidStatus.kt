package io.github.remmerw.asen.quic

internal enum class CidStatus {
    NEW,
    IN_USE,
    USED,
    RETIRED;

    fun active(): Boolean {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "Connection IDs that are issued and not retired are considered active;..."
        return this != RETIRED
    }
}

