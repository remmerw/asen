package io.github.remmerw.asen.core

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

        var colon: Int
        var ch: Char
        var sawDigit: Boolean
        var value: Int
        val srcb = src.toCharArray()
        val dst = ByteArray(INADDR16SZ)

        var srcbLength = srcb.size
        val pc = src.indexOf('%')
        if (pc == srcbLength - 1) {
            return null
        }

        if (pc != -1) {
            srcbLength = pc
        }

        colon = -1
        var i = 0
        var j = 0
        /* Leading :: requires some special handling. */
        if (srcb[i] == ':') if (srcb[++i] != ':') return null
        var token = i
        sawDigit = false
        value = 0
        while (i < srcbLength) {
            ch = srcb[i++]
            val chval = digit(ch, 16)
            if (chval != -1) {
                value = value shl 4
                value = value or chval
                if (value > 0xffff) return null
                sawDigit = true
                continue
            }
            if (ch == ':') {
                token = i
                if (!sawDigit) {
                    if (colon != -1) return null
                    colon = j
                    continue
                } else if (i == srcbLength) {
                    return null
                }
                if (j + INT16SZ > INADDR16SZ) return null
                dst[j++] = ((value shr 8) and 0xff).toByte()
                dst[j++] = (value and 0xff).toByte()
                sawDigit = false
                value = 0
                continue
            }
            if (ch == '.' && ((j + INADDR4SZ) <= INADDR16SZ)) {
                val ia4 = src.substring(token, srcbLength)
                /* check this IPv4 address has 3 dots, i.e. A.B.C.D */
                var dotCount = 0
                var index = 0
                while ((ia4.indexOf('.', index).also { index = it }) != -1) {
                    dotCount++
                    index++
                }
                if (dotCount != 3) {
                    return null
                }
                val v4addr = textToNumericFormatV4(ia4) ?: return null
                for (k in 0..<INADDR4SZ) {
                    dst[j++] = v4addr[k]
                }
                sawDigit = false
                break /* '\0' was seen by inet_pton4(). */
            }
            return null
        }
        if (sawDigit) {
            if (j + INT16SZ > INADDR16SZ) return null
            dst[j++] = ((value shr 8) and 0xff).toByte()
            dst[j++] = (value and 0xff).toByte()
        }

        if (colon != -1) {
            val n = j - colon

            if (j == INADDR16SZ) return null
            i = 1
            while (i <= n) {
                dst[INADDR16SZ - i] = dst[colon + n - i]
                dst[colon + n - i] = 0
                i++
            }
            j = INADDR16SZ
        }
        if (j != INADDR16SZ) return null
        val mapped = convertFromIPv4MappedAddress(dst)
        return mapped ?: dst
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
     * @param addr a String representing an IPv4-Mapped address in textual format
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
        return if (ALLOW_AMBIGUOUS_IPADDRESS_LITERALS_SP_VALUE) {
            ch.digitToIntOrNull(radix) ?: -1
        } else {
            parseAsciiDigit(ch, radix)
        }
    }

    // Parse ASCII digit in given radix
    fun parseAsciiDigit(c: Char, radix: Int): Int {
        require(radix == OCTAL || radix == DECIMAL || radix == HEXADECIMAL)
        if (radix == HEXADECIMAL) {
            return parseAsciiHexDigit(c)
        }
        val diff = c.code - '0'.code
        return if (diff !in 0..<radix) -1 else diff
    }

    // Parse ASCII digit in hexadecimal radix
    private fun parseAsciiHexDigit(digit: Char): Int {
        val c = digit.lowercaseChar()
        if (c in 'a'..'f') {
            return c.code - 'a'.code + 10
        }
        return parseAsciiDigit(c, DECIMAL)
    }

    // Supported radixes
    private const val HEXADECIMAL = 16
    private const val DECIMAL = 10
    private const val OCTAL = 8


    private const val ALLOW_AMBIGUOUS_IPADDRESS_LITERALS_SP_VALUE = false


}