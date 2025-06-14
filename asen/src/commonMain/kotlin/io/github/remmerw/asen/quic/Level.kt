package io.github.remmerw.asen.quic


/**
 * Level combines two concepts: PnSpace (Packet Numbers and Encryption Levels)
 *
 *
 * Packet numbers are divided into three spaces in QUIC.
 *
 *
 * See [...](https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers):
 * Initial space: All Initial packets (Section 17.2.2) are in this space.
 * Handshake space: All Handshake packets (Section 17.2.4) are in this space.
 * Application data space: All 0-RTT (Section 17.2.3) and 1-RTT (Section 17.3.1) packets are in this space.
 *
 *
 * [...](https://tools.ietf.org/html/draft-ietf-quic-tls-29#section2.1)
 * "Data is protected using a number of encryption levels:
 * Initial Keys
 * Early Data (0-RTT) Keys  -> THIS IS NOT SUPPORTED IN THIS IMPLEMENTATION
 * Handshake Keys
 * Application Data (1-RTT) Keys"
 *
 *
 * [...](https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-12.2)
 * "...order of increasing encryption levels (Initial, 0-RTT, Handshake, 1-RTT...)"
 */
internal enum class Level {
    Initial,  // Initial Space and Initial Keys
    Handshake,  // Handshake Space and Handshake Keys
    App; // Application data space and Application Data (1-RTT) Keys

    companion object {
        const val LENGTH: Int = 3
        private val cached = entries.toTypedArray()

        fun levels(): Array<Level> {
            return cached
        }
    }
}
