package io.github.remmerw.asen.core

/**
 * Utility object for encoding and decoding data using the Base58 encoding scheme.
 *
 * Base58 is a binary-to-text encoding scheme used to represent large integers as alphanumeric text,
 * commonly used in cryptocurrencies like Bitcoin. It omits characters that can be easily visually
 * confused, like '0', 'O', 'I', and 'l', and the result is case-sensitive.
 *
 * This implementation uses a custom alphabet consisting of 58 characters:
 * "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 *
 * The object provides methods to:
 * - `encode58`: Encode a byte array to a Base58 string.
 * - `decode58`: Decode a Base58 string to a byte array.
 * - `divmod`: A private utility function to perform division with remainder on byte arrays,
 *             used in both encoding and decoding.
 */
internal object Base58 {

    private const val ALPHABET_STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val ALPHABET = ALPHABET_STRING.toCharArray()
    private const val ENCODED_ZERO = '1'
    private val INDEXES = createIndexes()

    private fun createIndexes(): IntArray {
        val indexes = IntArray(128) { -1 }
        for (i in ALPHABET.indices) {
            indexes[ALPHABET[i].code] = i
        }
        return indexes
    }

    /**
     * Encodes the given byte array to a Base58 string.
     *
     * @param data The byte array to encode.
     * @return The Base58 encoded string.
     * @throws IllegalArgumentException if the input data is null.
     */
    fun encode58(data: ByteArray): String {
        requireNotNull(data) { "Input data cannot be null." }
        if (data.isEmpty()) {
            return ""
        }

        // Count leading zeros.
        val leadingZeros = data.takeWhile { it.toInt() == 0 }.count()

        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        val input = data.copyOf() // Create a copy to avoid modifying the original data
        val encoded = CharArray(input.size * 2) // upper bound
        var outputStart = encoded.size
        var inputStart = leadingZeros
        while (inputStart < input.size) {
            val remainder = divmod(input, inputStart, 256, 58)
            encoded[--outputStart] = ALPHABET[remainder.toInt()]
            if (input[inputStart].toInt() == 0) {
                inputStart++ // optimization - skip leading zeros
            }
        }

        // Preserve leading encoded zeros.
        while (outputStart < encoded.size && encoded[outputStart] == ENCODED_ZERO) {
            outputStart++
        }

        repeat(leadingZeros) {
            encoded[--outputStart] = ENCODED_ZERO
        }

        // Return encoded string (including encoded leading zeros).
        return encoded.concatToString(outputStart, encoded.size)
    }

    /**
     * Decodes the given Base58 string to a byte array.
     *
     * @param input The Base58 encoded string to decode.
     * @return The decoded byte array.
     * @throws IllegalArgumentException if the input string is null.
     * @throws IllegalArgumentException if the input string contains invalid Base58 characters.
     */
    fun decode58(input: String): ByteArray {
        requireNotNull(input) { "Input string cannot be null." }
        if (input.isEmpty()) {
            return byteArrayOf()
        }

        // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
        val input58 = ByteArray(input.length)
        for (i in input.indices) {
            val charCode = input[i].code
            val digit = if (charCode < 128) INDEXES[charCode] else -1
            if (digit < 0) {
                throw IllegalArgumentException("Invalid character in Base58: '${input[i]}'")
            }
            input58[i] = digit.toByte()
        }

        // Count leading zeros.
        val leadingZeros = input58.takeWhile { it.toInt() == 0 }.count()

        // Convert base-58 digits to base-256 digits.
        val decoded = ByteArray(input.length)
        var outputStart = decoded.size
        var inputStart = leadingZeros
        while (inputStart < input58.size) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256)
            if (input58[inputStart].toInt() == 0) {
                inputStart++ // optimization - skip leading zeros
            }
        }

        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.size && decoded[outputStart].toInt() == 0) {
            outputStart++
        }

        // Return decoded data (including original number of leading zeros).
        return decoded.copyOfRange(outputStart - leadingZeros, decoded.size)
    }

    /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number The number to divide.
     * @param firstDigit The index within the array of the first non-zero digit
     *   (this is used for optimization by skipping the leading zeros).
     * @param base The base in which the number's digits are represented (up to 256).
     * @param divisor The number to divide by (up to 256).
     * @return The remainder of the division operation.
     * @throws IllegalArgumentException if the divisor is zero.
     */
    private fun divmod(number: ByteArray, firstDigit: Int, base: Int, divisor: Int): Byte {
        require(divisor != 0) { "Divisor cannot be zero." }
        // this is just long division which accounts for the base of the input digits
        var remainder = 0
        for (i in firstDigit until number.size) {
            val digit = number[i].toInt() and 0xFF
            val temp = remainder * base + digit
            number[i] = (temp / divisor).toByte()
            remainder = temp % divisor
        }
        return remainder.toByte()
    }
}