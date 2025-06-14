package io.github.remmerw.asen.crypto

import org.kotlincrypto.random.CryptoRand


const val SECRET_KEY_LEN: Int = Field25519.FIELD_LEN
const val PUBLIC_KEY_LEN: Int = Field25519.FIELD_LEN
const val SIGNATURE_LEN: Int = Field25519.FIELD_LEN * 2


/**
 * Returns a random byte array of size `size`.
 */

internal fun randBytes(size: Int): ByteArray {
    return CryptoRand.Default.nextBytes(ByteArray(size))
}


/**
 * @param data the byte array to be wrapped.
 * @return an immutable wrapper around the provided bytes.
 */
internal fun copyFrom(data: ByteArray): Bytes {
    return copyFrom(data, 0, data.size)
}

/**
 * Wrap an immutable byte array over a slice of a Bytes
 *
 * @param data  the byte array to be wrapped.
 * @param start the starting index of the slice
 * @param length   the length of the slice. If start + len is larger than the size of `data`, the
 * remaining data will be returned.
 * @return an immutable wrapper around the bytes in the slice from `start` to `start +
 * len`
 */
internal fun copyFrom(data: ByteArray, start: Int, length: Int): Bytes {
    var len = length
    if (start + len > data.size) {
        len = data.size - start
    }
    return Bytes(data, start, len)
}

/**
 * Best effort fix-timing array comparison.
 *
 * @return true if two arrays are equal.
 */

internal fun equal(x: ByteArray, y: ByteArray): Boolean {
    return x.contentEquals(y)
}

/**
 * Returns the concatenation of the input arrays in a single array. For example, `concat(new
 * byte[] {a, b}, new byte[] {}, new byte[] {c}` returns the array `{a, b, c}`.
 *
 * @return a single array containing all the values from the source arrays, in order
 */
internal fun concat(vararg chunks: ByteArray): ByteArray {
    var length = 0
    for (chunk in chunks) {
        if (length > Int.MAX_VALUE - chunk.size) {
            throw Exception("exceeded size limit")
        }
        length += chunk.size
    }
    val res = ByteArray(length)
    var pos = 0
    for (chunk in chunks) {
        chunk.copyInto(res, pos, 0, chunk.size)
        pos += chunk.size
    }
    return res
}

/**
 * Conditionally copies a reduced-form limb arrays `b` into `a` if `icopy` is 1,
 * but leave `a` unchanged if 'iswap' is 0. Runs in data-invariant time to avoid
 * side-channel attacks.
 *
 *
 * NOTE that this function requires that `icopy` be 1 or 0; other values give wrong
 * results. Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the
 * values in a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must
 * have magnitude less than Integer.MAX_VALUE.
 */

internal fun copyConditional(a: LongArray, b: LongArray, icopy: Int) {
    val copy = -icopy
    for (i in 0 until Field25519.LIMB_CNT) {
        val x = copy and ((a[i].toInt()) xor (b[i].toInt()))
        a[i] = ((a[i].toInt()) xor x).toLong()
    }
}
