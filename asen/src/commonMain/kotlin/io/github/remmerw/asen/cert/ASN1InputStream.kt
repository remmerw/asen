package io.github.remmerw.asen.cert

/**
 * A general purpose ASN.1 decoder - note: this class differs from the
 * others in that it returns null after it has read the last object in
 * the stream. If an ASN.1 NULL is encountered a DER/BER Null object is
 * returned.
 */


/**
 * Create an ASN1InputStream where no DER object will be longer than limit, and constructed
 * objects such as sequences will be parsed lazily.
 *
 * @param input stream containing ASN.1 encoded data.
 * @param limit maximum size of a DER encoded object.
 */
internal class ASN1InputStream(
    val input: Input,
    private val limit: Int,
    private val tmpBuffers: Array<ByteArray?> = arrayOfNulls(11)
) :
    BERTags {


    private fun readLength(): Int {
        return readLength(input, limit)
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     *
     * @param tag    the full tag details.
     * @param tagNo  the tagNo defined.
     * @param length the length of the object.
     * @return the resulting primitive.
     */

    private fun buildObject(
        tag: Int,
        tagNo: Int,
        length: Int
    ): ASN1Primitive {
        val defIn = DefiniteLengthInputStream(
            input, length,
            limit
        )

        if (0 == (tag and BERTags.FLAGS)) {
            return createPrimitiveDERObject(tagNo, defIn, tmpBuffers)
        }


        return when (tagNo) {
            BERTags.BIT_STRING -> {
                buildConstructedBitString(readVector(defIn))
            }

            BERTags.OCTET_STRING -> {
                //
                // yes, people actually do this...
                //
                buildConstructedOctetString(readVector(defIn))
            }

            BERTags.SEQUENCE -> {
                if (defIn.remaining < 1) {
                    EMPTY_SEQUENCE
                } else {
                    createSequence(readVector(defIn))
                }
            }

            BERTags.SET -> {
                createSet(readVector(defIn))
            }

            else -> throw Exception("unknown tag $tagNo encountered")
        }
    }


    fun readObject(): ASN1Primitive? {
        val tag = input.read()
        if (tag <= 0) {
            if (tag == 0) {
                throw Exception("unexpected end-of-contents marker")
            }

            return null
        }

        val tagNo = readTagNumber(input, tag)
        val length = readLength()

        if (length >= 0) {
            // definite-length
            return buildObject(tag, tagNo, length)
        }
        throw Exception("not supported stream detected")
    }


    private fun readVector(): ASN1EncodableVector {
        var p: ASN1Primitive? = readObject() ?: return ASN1EncodableVector()

        val v = ASN1EncodableVector()
        do {
            v.add(p!!)
        } while ((readObject().also { p = it }) != null)
        return v
    }


    private fun readVector(defIn: DefiniteLengthInputStream): ASN1EncodableVector {
        val remaining = defIn.remaining
        if (remaining < 1) {
            return ASN1EncodableVector()
        }

        return ASN1InputStream(defIn, remaining, tmpBuffers).readVector()
    }


    private fun readTagNumber(s: Input, tag: Int): Int {
        var tagNo = tag and 0x1f

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f) {
            var b = s.read()
            if (b < 31) {
                if (b < 0) {
                    throw Exception("EOF found inside tag value.")
                }
                throw Exception("corrupted stream - high tag number < 31 found")
            }

            tagNo = b and 0x7f

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if (0 == tagNo) {
                throw Exception("corrupted stream - invalid high tag number found")
            }

            while ((b and 0x80) != 0) {
                if ((tagNo ushr 24) != 0) {
                    throw Exception("Tag number more than 31 bits")
                }

                tagNo = tagNo shl 7

                b = s.read()
                if (b < 0) {
                    throw Exception("EOF found inside tag value.")
                }

                tagNo = tagNo or (b and 0x7f)
            }
        }

        return tagNo
    }


    private fun readLength(s: Input, limit: Int): Int {
        var length = s.read()
        if (0 == (length ushr 7)) {
            // definite-length short form
            return length
        }
        if (0x80 == length) {
            // indefinite-length
            return -1
        }
        if (length < 0) {
            throw Exception("EOF found when length expected")
        }
        if (0xFF == length) {
            throw Exception("invalid long form definite-length 0xFF")
        }

        val octetsCount = length and 0x7F
        var octetsPos = 0

        length = 0
        do {
            val octet = s.read()
            if (octet < 0) {
                throw Exception("EOF found reading length")
            }

            if ((length ushr 23) != 0) {
                throw Exception("long form definite-length more than 31 bits")
            }

            length = (length shl 8) + octet
        } while (++octetsPos < octetsCount)

        if (length >= limit)  // after all we must have read at least 1 byte
        {
            throw Exception("corrupted stream - out of bounds length found: $length >= $limit")
        }

        return length
    }


    private fun getBuffer(
        defIn: DefiniteLengthInputStream,
        tmpBuffers: Array<ByteArray?>
    ): ByteArray {
        val len = defIn.remaining
        if (len >= tmpBuffers.size) {
            return defIn.toByteArray()
        }

        var buf = tmpBuffers[len]
        if (buf == null) {
            tmpBuffers[len] = ByteArray(len)
            buf = tmpBuffers[len]
        }

        defIn.readAllIntoByteArray(buf!!)

        return buf
    }


    private fun getBMPCharBuffer(defIn: DefiniteLengthInputStream): CharArray {
        var remainingBytes = defIn.remaining
        if (0 != (remainingBytes and 1)) {
            throw Exception("malformed BMPString encoding encountered")
        }

        val string = CharArray(remainingBytes / 2)
        var stringPos = 0

        val buf = ByteArray(8)
        while (remainingBytes >= 8) {
            if (readFully(defIn, buf, 0, 8) != 8) {
                throw Exception("EOF encountered in middle of BMPString")
            }

            string[stringPos] = ((buf[0].toInt() shl 8) or (buf[1].toInt() and 0xFF)).toChar()
            string[stringPos + 1] =
                ((buf[2].toInt() shl 8) or (buf[3].toInt() and 0xFF)).toChar()
            string[stringPos + 2] =
                ((buf[4].toInt() shl 8) or (buf[5].toInt() and 0xFF)).toChar()
            string[stringPos + 3] =
                ((buf[6].toInt() shl 8) or (buf[7].toInt() and 0xFF)).toChar()
            stringPos += 4
            remainingBytes -= 8
        }
        if (remainingBytes > 0) {
            if (readFully(defIn, buf, 0, remainingBytes) != remainingBytes) {
                throw Exception("EOF encountered in middle of BMPString")
            }

            var bufPos = 0
            do {
                val b1 = buf[bufPos++].toInt() shl 8
                val b2 = buf[bufPos++].toInt() and 0xFF
                string[stringPos++] = (b1 or b2).toChar()
            } while (bufPos < remainingBytes)
        }

        check(!(0 != defIn.remaining || string.size != stringPos))

        return string
    }


    private fun createPrimitiveDERObject(
        tagNo: Int,
        defIn: DefiniteLengthInputStream,
        tmpBuffers: Array<ByteArray?>
    ): ASN1Primitive {
        return when (tagNo) {
            BERTags.BIT_STRING -> ASN1BitString.createPrimitive(defIn.toByteArray())
            BERTags.BMP_STRING -> DERBMPString(getBMPCharBuffer(defIn))
            BERTags.BOOLEAN -> ASN1Boolean.createPrimitive(getBuffer(defIn, tmpBuffers))
            BERTags.ENUMERATED -> ASN1Enumerated.createPrimitive(getBuffer(defIn, tmpBuffers))
            BERTags.GENERAL_STRING -> ASN1GeneralString.createPrimitive(defIn.toByteArray())
            BERTags.GENERALIZED_TIME -> ASN1GeneralizedTime.createPrimitive(defIn.toByteArray())
            BERTags.GRAPHIC_STRING -> ASN1GraphicString.createPrimitive(defIn.toByteArray())
            BERTags.IA5_STRING -> ASN1IA5String.createPrimitive(defIn.toByteArray())
            BERTags.INTEGER -> ASN1Integer(defIn.toByteArray())
            BERTags.NULL -> {
                check(defIn.toByteArray().isEmpty()) { "malformed NULL encoding encountered" }
                return DERNull.INSTANCE
            }

            BERTags.NUMERIC_STRING -> DERNumericString(defIn.toByteArray())
            BERTags.OBJECT_DESCRIPTOR -> ASN1ObjectDescriptor.createPrimitive(defIn.toByteArray())
            BERTags.OBJECT_IDENTIFIER -> ASN1ObjectIdentifier.createPrimitive(
                getBuffer(
                    defIn,
                    tmpBuffers
                )
            )

            BERTags.OCTET_STRING -> DEROctetString(defIn.toByteArray())
            BERTags.PRINTABLE_STRING -> ASN1PrintableString.createPrimitive(defIn.toByteArray())
            BERTags.RELATIVE_OID -> ASN1RelativeOID(defIn.toByteArray())
            BERTags.T61_STRING -> ASN1T61String.createPrimitive(defIn.toByteArray())
            BERTags.UNIVERSAL_STRING -> ASN1UniversalString.createPrimitive(defIn.toByteArray())
            BERTags.UTC_TIME -> ASN1UTCTime.createPrimitive(defIn.toByteArray())
            BERTags.UTF8_STRING -> ASN1UTF8String.createPrimitive(defIn.toByteArray())
            BERTags.VIDEOTEX_STRING -> ASN1VideotexString.createPrimitive(defIn.toByteArray())
            BERTags.VISIBLE_STRING -> ASN1VisibleString.createPrimitive(defIn.toByteArray())
            else -> throw Exception("unknown tag $tagNo encountered")
        }
    }


    private fun buildConstructedBitString(contentsElements: ASN1EncodableVector): ASN1BitString {
        val strings = mutableListOf<ASN1BitString>()

        for (i in 0 until contentsElements.size()) {
            val asn1Obj = contentsElements.get(i)
            if (asn1Obj is ASN1BitString) {
                strings.add(asn1Obj)
            } else {
                throw Exception("unknown object encountered in constructed")
            }
        }
        return BERBitString(strings.toTypedArray())
    }


    private fun buildConstructedOctetString(contentsElements: ASN1EncodableVector): ASN1OctetString {
        val strings = mutableListOf<ASN1OctetString>()

        for (i in 0 until contentsElements.size()) {
            val asn1Obj = contentsElements.get(i)
            if (asn1Obj is ASN1OctetString) {
                strings.add(asn1Obj)
            } else {
                throw Exception("unknown object encountered in constructed")
            }
        }

        return BEROctetString(strings.toTypedArray())
    }

}
