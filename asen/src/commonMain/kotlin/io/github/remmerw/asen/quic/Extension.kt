package io.github.remmerw.asen.quic

/**
 * A TLS Extension.
 * See [...](https://tools.ietf.org/html/rfc8446#section-4.2)
 */
internal interface Extension {
    fun getBytes(): ByteArray
    fun extension(): ExtensionClass
}

/**
 * TLS Pre-Shared Key extension.
 * see [...](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11)
 */
internal interface PreSharedKeyExtension : Extension
