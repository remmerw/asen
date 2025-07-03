package io.github.remmerw.asen.quic

// todo should be replace with a real implementation of a library
data class X509Certificate(val data: ByteArray) {

    companion object {
        fun decodeFromDer(byteArray: ByteArray): X509Certificate {
            return X509Certificate(byteArray)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }
}