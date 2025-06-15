package io.github.remmerw.asen.core

import java.nio.CharBuffer
import java.util.Arrays

object AddressUtil {
    private const val INADDR4SZ = 4
    private const val INADDR16SZ = 16
    private const val INT16SZ = 2

    /**
     * Converts IPv4 address in its textual presentation form
     * into its numeric binary form.
     *
     * @param src a String representing an IPv4 address in standard format
     * @return a byte array representing the IPv4 numeric address
     */
    fun textToNumericFormatV4(src: String): ByteArray? {
        val res = ByteArray(INADDR4SZ)

        var tmpValue: Long = 0
        var currByte = 0
        var newOctet = true

        val len = src.length
        if (len == 0 || len > 15) {
            return null
        }
        /*
         * When only one part is given, the value is stored directly in
         * the network address without any byte rearrangement.
         *
         * When a two part address is supplied, the last part is
         * interpreted as a 24-bit quantity and placed in the right
         * most three bytes of the network address. This makes the
         * two part address format convenient for specifying Class A
         * network addresses as net.host.
         *
         * When a three part address is specified, the last part is
         * interpreted as a 16-bit quantity and placed in the right
         * most two bytes of the network address. This makes the
         * three part address format convenient for specifying
         * Class B net- work addresses as 128.net.host.
         *
         * When four parts are specified, each is interpreted as a
         * byte of data and assigned, from left to right, to the
         * four bytes of an IPv4 address.
         *
         * We determine and parse the leading parts, if any, as single
         * byte values in one pass directly into the resulting byte[],
         * then the remainder is treated as a 8-to-32-bit entity and
         * translated into the remaining bytes in the array.
         */
        for (i in 0..<len) {
            val c = src[i]
            if (c == '.') {
                if (newOctet || tmpValue < 0 || tmpValue > 0xff || currByte == 3) {
                    return null
                }
                res[currByte++] = (tmpValue and 0xffL).toByte()
                tmpValue = 0
                newOctet = true
            } else {
                val digit = digit(c, 10)
                if (digit < 0) {
                    return null
                }
                tmpValue *= 10
                tmpValue += digit.toLong()
                newOctet = false
            }
        }
        if (newOctet || tmpValue < 0 || tmpValue >= (1L shl ((4 - currByte) * 8))) {
            return null
        }
        when (currByte) {
            0 -> {
                res[0] = ((tmpValue shr 24) and 0xffL).toByte()
                res[1] = ((tmpValue shr 16) and 0xffL).toByte()
                res[2] = ((tmpValue shr 8) and 0xffL).toByte()
                res[3] = ((tmpValue shr 0) and 0xffL).toByte()
            }

            1 -> {
                res[1] = ((tmpValue shr 16) and 0xffL).toByte()
                res[2] = ((tmpValue shr 8) and 0xffL).toByte()
                res[3] = ((tmpValue shr 0) and 0xffL).toByte()
            }

            2 -> {
                res[2] = ((tmpValue shr 8) and 0xffL).toByte()
                res[3] = ((tmpValue shr 0) and 0xffL).toByte()
            }

            3 -> res[3] = ((tmpValue shr 0) and 0xffL).toByte()
        }
        return res
    }

    /**
     * Validates if input string is a valid IPv4 address literal.
     * If the "jdk.net.allowAmbiguousIPAddressLiterals" system property is set
     * to `false`, or is not set then validation of the address string is performed as follows:
     * If string can't be parsed by following IETF IPv4 address string literals
     * formatting style rules (default one), but can be parsed by following BSD formatting
     * style rules, the IPv4 address string content is treated as ambiguous and
     * either `IllegalArgumentException` is thrown, or `null` is returned.
     *
     * @param src input string
     * @param throwIAE `true` - throw `IllegalArgumentException` when cannot be parsed
     * as IPv4 address string;
     * `false` - throw `IllegalArgumentException` only when IPv4 address
     * string is ambiguous.
     * @return bytes array if string is a valid IPv4 address string
     * @throws IllegalArgumentException if "jdk.net.allowAmbiguousIPAddressLiterals" SP is set to
     * `false`, IPv4 address string `src` is ambiguous,
     * or when address string cannot be parsed as an IPv4 address
     * string and `throwIAE` is set to `true`.
     */
    fun validateNumericFormatV4(src: String, throwIAE: Boolean): ByteArray? {
        val parsedBytes = textToNumericFormatV4(src)
        if (!ALLOW_AMBIGUOUS_IPADDRESS_LITERALS_SP_VALUE && parsedBytes == null && isBsdParsableV4(
                src
            )
        ) {
            throw invalidIpAddressLiteral(src)
        }
        if (parsedBytes == null && throwIAE) {
            throw invalidIpAddressLiteral(src)
        }
        return parsedBytes
    }

    /**
     * Creates `IllegalArgumentException` with invalid IP address literal message.
     *
     * @param src address literal string to include to the exception message
     * @return an `IllegalArgumentException` instance
     */
    fun invalidIpAddressLiteral(src: String?): IllegalArgumentException {
        return IllegalArgumentException("Invalid IP address literal")
    }

    /**
     * Convert IPv6 presentation level address to network order binary form.
     * credit:
     *  Converted from C code from Solaris 8 (inet_pton)
     *
     * Any component of the string following a per-cent % is ignored.
     *
     * @param src a String representing an IPv6 address in textual format
     * @return a byte array representing the IPv6 numeric address
     */
    fun textToNumericFormatV6(src: String): ByteArray? {
        // Shortest valid string is "::", hence at least 2 chars
        if (src.length < 2) {
            return null
        }

        var colonp: Int
        var ch: Char
        var saw_xdigit: Boolean
        var `val`: Int
        val srcb = src.toCharArray()
        val dst = ByteArray(INADDR16SZ)

        var srcb_length = srcb.size
        val pc = src.indexOf('%')
        if (pc == srcb_length - 1) {
            return null
        }

        if (pc != -1) {
            srcb_length = pc
        }

        colonp = -1
        var i = 0
        var j = 0
        /* Leading :: requires some special handling. */
        if (srcb[i] == ':') if (srcb[++i] != ':') return null
        var curtok = i
        saw_xdigit = false
        `val` = 0
        while (i < srcb_length) {
            ch = srcb[i++]
            val chval = digit(ch, 16)
            if (chval != -1) {
                `val` = `val` shl 4
                `val` = `val` or chval
                if (`val` > 0xffff) return null
                saw_xdigit = true
                continue
            }
            if (ch == ':') {
                curtok = i
                if (!saw_xdigit) {
                    if (colonp != -1) return null
                    colonp = j
                    continue
                } else if (i == srcb_length) {
                    return null
                }
                if (j + INT16SZ > INADDR16SZ) return null
                dst[j++] = ((`val` shr 8) and 0xff).toByte()
                dst[j++] = (`val` and 0xff).toByte()
                saw_xdigit = false
                `val` = 0
                continue
            }
            if (ch == '.' && ((j + INADDR4SZ) <= INADDR16SZ)) {
                val ia4 = src.substring(curtok, srcb_length)
                /* check this IPv4 address has 3 dots, i.e. A.B.C.D */
                var dot_count = 0
                var index = 0
                while ((ia4.indexOf('.', index).also { index = it }) != -1) {
                    dot_count++
                    index++
                }
                if (dot_count != 3) {
                    return null
                }
                val v4addr = textToNumericFormatV4(ia4)
                if (v4addr == null) {
                    return null
                }
                for (k in 0..<INADDR4SZ) {
                    dst[j++] = v4addr[k]
                }
                saw_xdigit = false
                break /* '\0' was seen by inet_pton4(). */
            }
            return null
        }
        if (saw_xdigit) {
            if (j + INT16SZ > INADDR16SZ) return null
            dst[j++] = ((`val` shr 8) and 0xff).toByte()
            dst[j++] = (`val` and 0xff).toByte()
        }

        if (colonp != -1) {
            val n = j - colonp

            if (j == INADDR16SZ) return null
            i = 1
            while (i <= n) {
                dst[INADDR16SZ - i] = dst[colonp + n - i]
                dst[colonp + n - i] = 0
                i++
            }
            j = INADDR16SZ
        }
        if (j != INADDR16SZ) return null
        val newdst = convertFromIPv4MappedAddress(dst)
        if (newdst != null) {
            return newdst
        } else {
            return dst
        }
    }

    /**
     * @param src a String representing an IPv4 address in textual format
     * @return a boolean indicating whether src is an IPv4 literal address
     */
    fun isIPv4LiteralAddress(src: String): Boolean {
        return textToNumericFormatV4(src) != null
    }

    /**
     * @param src a String representing an IPv6 address in textual format
     * @return a boolean indicating whether src is an IPv6 literal address
     */
    fun isIPv6LiteralAddress(src: String): Boolean {
        return textToNumericFormatV6(src) != null
    }

    /**
     * Convert IPv4-Mapped address to IPv4 address. Both input and
     * returned value are in network order binary form.
     *
     * @param src a String representing an IPv4-Mapped address in textual format
     * @return a byte array representing the IPv4 numeric address
     */
    fun convertFromIPv4MappedAddress(addr: ByteArray): ByteArray? {
        if (isIPv4MappedAddress(addr)) {
            return addr.copyOfRange(12, addr.size)
        }
        return null
    }

    /**
     * Utility routine to check if the InetAddress is an
     * IPv4 mapped IPv6 address.
     *
     * @return a `boolean` indicating if the InetAddress is
     * an IPv4 mapped IPv6 address; or false if address is IPv4 address.
     */
    private fun isIPv4MappedAddress(addr: ByteArray): Boolean {
        if (addr.size < INADDR16SZ) {
            return false
        }
        if ((addr[0].toInt() == 0x00) && (addr[1].toInt() == 0x00) &&
            (addr[2].toInt() == 0x00) && (addr[3].toInt() == 0x00) &&
            (addr[4].toInt() == 0x00) && (addr[5].toInt() == 0x00) &&
            (addr[6].toInt() == 0x00) && (addr[7].toInt() == 0x00) &&
            (addr[8].toInt() == 0x00) && (addr[9].toInt() == 0x00) &&
            (addr[10] == 0xff.toByte()) &&
            (addr[11] == 0xff.toByte())
        ) {
            return true
        }
        return false
    }


    // Tell whether the given character is found by the given mask pair
    fun match(c: Char, lowMask: Long, highMask: Long): Boolean {
        if (c.code < 64) return ((1L shl c.code) and lowMask) != 0L
        if (c.code < 128) return ((1L shl (c.code - 64)) and highMask) != 0L
        return false // other non ASCII characters are not filtered
    }

    // returns -1 if the string doesn't contain any characters
    // from the mask, the index of the first such character found
    // otherwise.
    fun scan(s: String?, lowMask: Long, highMask: Long): Int {
        var i = -1
        var len: Int = 0
        if (s == null || (s.length.also { len = it }) == 0) return -1
        var match = false
        while (++i < len && !(match(s.get(i), lowMask, highMask).also { match = it }));
        if (match) return i
        return -1
    }

    fun scan(s: String?, lowMask: Long, highMask: Long, others: CharArray): Int {
        var i = -1
        var len: Int = 0
        if (s == null || (s.length.also { len = it }) == 0) return -1
        var match = false
        var c: Char = 0.toChar()
        val c0 = others[0]
        while (++i < len && !(match((s.get(i).also { c = it }), lowMask, highMask).also {
                match = it
            })) {
            if (c >= c0 && (Arrays.binarySearch(others, c) > -1)) {
                match = true
                break
            }
        }
        if (match) return i

        return -1
    }


    /**
     * Returns the numeric value of the character `ch` in the
     * specified radix.
     *
     * @param ch    the character to be converted.
     * @param radix the radix.
     * @return the numeric value represented by the character in the
     * specified radix.
     */
    fun digit(ch: Char, radix: Int): Int {
        if (ALLOW_AMBIGUOUS_IPADDRESS_LITERALS_SP_VALUE) {
            return ch.digitToIntOrNull(radix) ?: -1
        } else {
            return parseAsciiDigit(ch, radix)
        }
    }

    /**
     * Try to parse String as IPv4 address literal by following
     * BSD-style formatting rules.
     *
     * @param input input string
     * @return `true` if input string is parsable as IPv4 address literal,
     * `false` otherwise.
     */
    fun isBsdParsableV4(input: String): Boolean {
        return parseBsdLiteralV4(input) != null
    }

    /**
     * Parse String as IPv4 address literal by following
     * POSIX-style formatting rules.
     *
     * @param input a String representing an IPv4 address in POSIX format
     * @return a byte array representing the IPv4 numeric address
     * if input string is a parsable POSIX formatted IPv4 address literal,
     * `null` otherwise.
     */
    fun parseBsdLiteralV4(input: String): ByteArray? {
        val res = byteArrayOf(0, 0, 0, 0)

        val len = input.length
        if (len == 0) {
            return null
        }
        val firstSymbol = input.get(0)
        // Check if first digit is not a decimal digit
        if (parseAsciiDigit(firstSymbol, DECIMAL) == -1) {
            return null
        }

        // Last character is dot OR is not a supported digit: [0-9,A-F,a-f]
        val lastSymbol = input.get(len - 1)
        if (lastSymbol == '.' || parseAsciiHexDigit(lastSymbol) == -1) {
            return null
        }

        // Parse IP address fields
        val charBuffer = CharBuffer.wrap(input)
        var fieldNumber = 0
        var fieldValue = -1L
        while (charBuffer.hasRemaining()) {
            fieldValue = -1L
            // Try to parse fields in all supported radixes
            for (radix in SUPPORTED_RADIXES) {
                fieldValue = parseV4FieldBsd(radix, charBuffer, fieldNumber)
                if (fieldValue >= 0) {
                    if (fieldValue < 256) {
                        // Store the parsed field in the byte buffer.
                        // If the field value is greater than 255, it can only be the last field.
                        // If it is not the last one, parseV4FieldBsd enforces this limit
                        // and returns TERMINAL_PARSE_ERROR.
                        res[fieldNumber] = fieldValue.toByte()
                    }
                    fieldNumber++
                    break
                } else if (fieldValue == TERMINAL_PARSE_ERROR) {
                    return null
                }
            }
            // If field can't be parsed as one of supported radixes stop
            // parsing
            if (fieldValue < 0) {
                return null
            }
        }
        // The last field value must be non-negative
        if (fieldValue < 0) {
            return null
        }
        // If the last fieldValue is greater than 255 (fieldNumber < 4),
        // it is written to the last (4 - (fieldNumber - 1)) octets
        // in the network order
        if (fieldNumber < 4) {
            for (i in 3 downTo fieldNumber - 1) {
                res[i] = (fieldValue and 255L).toByte()
                fieldValue = fieldValue shr 8
            }
        }
        return res
    }

    /**
     * Method tries to parse IP address field that starts from [ current position][java.nio.CharBuffer.position] of the provided character buffer.
     *
     *
     * This method supports three `"radix"` values to decode field values in
     * `"HEXADECIMAL (radix=16)"`, `"DECIMAL (radix=10)"` and
     * `"OCTAL (radix=8)"` radixes.
     *
     *
     * If `-1` value is returned the char buffer position is reset to the value
     * it was before it was called.
     *
     *
     * Method returns `-2` if formatting illegal for all supported `radix`
     * values is observed, and there is no point in checking other radix values.
     * That includes the following cases:
     *  * Two subsequent dots are observer
     *  * Number of dots more than 3
     *  * Field value exceeds max allowed
     *  * Character is not a valid digit for the requested `radix` value, given
     * that a field has the radix specific prefix
     *
     *
     * @param radix       digits encoding radix to use for parsing. Valid values: 8, 10, 16.
     * @param buffer      `CharBuffer` with position set to the field's fist character
     * @param fieldNumber parsed field number
     * @return `CANT_PARSE_IN_RADIX` if field can not be parsed in requested `radix`.
     * `TERMINAL_PARSE_ERROR` if field can't be parsed and the whole parse process should be terminated.
     * Parsed field value otherwise.
     */
    private fun parseV4FieldBsd(radix: Int, buffer: CharBuffer, fieldNumber: Int): Long {
        val initialPos = buffer.position()
        var `val`: Long = 0
        var digitsCount = 0
        if (!checkPrefix(buffer, radix)) {
            `val` = CANT_PARSE_IN_RADIX
        }
        var dotSeen = false
        while (buffer.hasRemaining() && `val` != CANT_PARSE_IN_RADIX && !dotSeen) {
            val c = buffer.get()
            if (c == '.') {
                dotSeen = true
                // Fail if 4 dots in IP address string.
                // fieldNumber counter starts from 0, therefore 3
                if (fieldNumber == 3) {
                    // Terminal state, can stop parsing: too many fields
                    return TERMINAL_PARSE_ERROR
                }
                // Check for literals with two dots, like '1.2..3', '1.2.3..'
                if (digitsCount == 0) {
                    // Terminal state, can stop parsing: dot with no digits
                    return TERMINAL_PARSE_ERROR
                }
                if (`val` > 255) {
                    // Terminal state, can stop parsing: too big value for an octet
                    return TERMINAL_PARSE_ERROR
                }
            } else {
                val dv = parseAsciiDigit(c, radix)
                if (dv >= 0) {
                    digitsCount++
                    `val` *= radix.toLong()
                    `val` += dv.toLong()
                } else {
                    // Spotted digit can't be parsed in the requested 'radix'.
                    // The order in which radixes are checked - hex, octal, decimal:
                    //    - if symbol is not a valid digit in hex radix - terminal
                    //    - if symbol is not a valid digit in octal radix, and given
                    //      that octal prefix was observed before - terminal
                    //    - if symbol is not a valid digit in decimal radix - terminal
                    return TERMINAL_PARSE_ERROR
                }
            }
        }
        if (`val` == CANT_PARSE_IN_RADIX) {
            buffer.position(initialPos)
        } else if (!dotSeen) {
            // It is the last field - check its value
            // This check will ensure that address strings with less
            // than 4 fields, i.e. A, A.B and A.B.C address types
            // contain value less then the allowed maximum for the last field.
            val maxValue = (1L shl ((4 - fieldNumber) * 8)) - 1
            if (`val` > maxValue) {
                //  Terminal state, can stop parsing: last field value exceeds its
                //  allowed value
                return TERMINAL_PARSE_ERROR
            }
        }
        return `val`
    }

    // This method moves the position of the supplied CharBuffer by analysing the digit prefix
    // symbols if any.
    // The caller should reset the position when method returns false.
    private fun checkPrefix(buffer: CharBuffer, radix: Int): Boolean {
        return when (radix) {
            OCTAL -> isOctalFieldStart(buffer)
            DECIMAL -> isDecimalFieldStart(buffer)
            HEXADECIMAL -> isHexFieldStart(buffer)
            else -> throw AssertionError("Not supported radix")
        }
    }

    // This method always moves the position of the supplied CharBuffer
    // removing the octal prefix symbols '0'.
    // The caller should reset the position when method returns false.
    private fun isOctalFieldStart(cb: CharBuffer): Boolean {
        // .0<EOS> is not treated as octal field
        if (cb.remaining() < 2) {
            return false
        }

        // Fetch two first characters
        val position = cb.position()
        val first = cb.get()
        val second = cb.get()

        // Return false if the first char is not octal prefix '0' or second is a
        // field separator - parseV4FieldBsd will reset position to start of the field.
        // '.0.' fields will be successfully parsed in decimal radix.
        val isOctalPrefix = first == '0' && second != '.'

        // If the prefix looks like octal - consume '0', otherwise 'false' is returned
        // and caller will reset the buffer position.
        if (isOctalPrefix) {
            cb.position(position + 1)
        }
        return isOctalPrefix
    }

    // This method doesn't move the position of the supplied CharBuffer
    private fun isDecimalFieldStart(cb: CharBuffer): Boolean {
        return cb.hasRemaining()
    }

    // This method always moves the position of the supplied CharBuffer
    // removing the hexadecimal prefix symbols '0x'.
    // The caller should reset the position when method returns false.
    private fun isHexFieldStart(cb: CharBuffer): Boolean {
        if (cb.remaining() < 2) {
            return false
        }
        val first = cb.get()
        val second = cb.get()
        return first == '0' && (second == 'x' || second == 'X')
    }

    // Parse ASCII digit in given radix
    fun parseAsciiDigit(c: Char, radix: Int): Int {
        assert(radix == OCTAL || radix == DECIMAL || radix == HEXADECIMAL)
        if (radix == HEXADECIMAL) {
            return parseAsciiHexDigit(c)
        }
        val `val` = c.code - '0'.code
        return if (`val` < 0 || `val` >= radix) -1 else `val`
    }

    // Parse ASCII digit in hexadecimal radix
    private fun parseAsciiHexDigit(digit: Char): Int {
        val c = digit.lowercaseChar()
        if (c >= 'a' && c <= 'f') {
            return c.code - 'a'.code + 10
        }
        return parseAsciiDigit(c, DECIMAL)
    }

    // Supported radixes
    private const val HEXADECIMAL = 16
    private const val DECIMAL = 10
    private const val OCTAL = 8

    // Order in which field formats are exercised to parse one IP address textual field
    private val SUPPORTED_RADIXES = intArrayOf(HEXADECIMAL, OCTAL, DECIMAL)

    // BSD parser's return values
    private const val CANT_PARSE_IN_RADIX = -1L
    private const val TERMINAL_PARSE_ERROR = -2L


    private const val ALLOW_AMBIGUOUS_IPADDRESS_LITERALS_SP_VALUE = false


}