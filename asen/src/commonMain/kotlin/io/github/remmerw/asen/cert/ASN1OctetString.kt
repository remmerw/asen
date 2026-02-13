package io.github.remmerw.asen.cert

/**
 * Abstract base for the ASN.1 OCTET STRING data payloadType
 *
 *
 * This supports BER, and DER forms of the data.
 *
 *
 * DER form is always primitive single OCTET STRING, while
 * BER support includes the constructed forms.
 *
 *
 * **X.690**
 *
 * **8: Basic encoding rules**
 *
 * **8.7 Encoding of an octet string value**
 *
 *
 * **8.7.1** The encoding of an octet string value shall be
 * either primitive or constructed at the option of the sender.
 * <blockquote>
 * NOTE  Where it is necessary to transfer part of an octet string
 * before the entire OCTET STRING is available, the constructed encoding
 * is used.
</blockquote> *
 *
 *
 * **8.7.2** The primitive encoding contains zero,
 * one or more contents octets equal in value to the octets
 * in the data value, in the order they appear in the data value,
 * and with the most significant bit of an octet of the data value
 * aligned with the most significant bit of an octet of the contents octets.
 *
 *
 *
 * **8.7.3** The contents octets for the constructed encoding shall consist
 * of zero, one, or more encodings.
 *
 * <blockquote>
 * NOTE  Each such encoding includes identifier, length, and contents octets,
 * and may include end-of-contents octets if it is constructed.
</blockquote> *
 *
 *
 * **8.7.3.1** To encode an octet string value in this way,
 * it is segmented. Each segment shall consist of a series of
 * consecutive octets of the value. There shall be no significance
 * placed on the segment boundaries.
 * <blockquote>
 * NOTE  A segment may be of size zero, i.e. contain no octets.
</blockquote> *
 *
 *
 * **8.7.3.2** Each encoding in the contents octets shall represent
 * a segment of the overall octet string, the encoding arising from
 * a recursive application of this subclause.
 * In this recursive application, each segment is treated as if it were
 * an octet string value. The encodings of the segments shall appear in the contents
 * octets in the order in which their octets appear in the overall value.
 *
 * <blockquote>
 * NOTE 1  As a consequence of this recursion,
 * each encoding in the contents octets may itself
 * be primitive or constructed.
 * However, such encodings will usually be primitive.
</blockquote> *
 * <blockquote>
 * NOTE 2  In particular, the tags in the contents octets are always universal class, number 4.
</blockquote> *
 *
 * **9: Canonical encoding rules**
 *
 * **9.1 Length forms**
 *
 *
 * If the encoding is constructed, it shall employ the indefinite-length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 *
 *
 * **9.2 String encoding forms**
 *
 *
 * BIT STRING, OCTET STRING,and restricted character string
 * values shall be encoded with a primitive encoding if they would
 * require no more than 1000 contents octets, and as a constructed
 * encoding otherwise. The string fragments contained in
 * the constructed encoding shall be encoded with a primitive encoding.
 * The encoding of each fragment, except possibly
 * the last, shall have 1000 contents octets. (Contrast with 8.21.6.)
 *
 *
 * **10: Distinguished encoding rules**
 *
 *
 * **10.1 Length forms**
 * The definite form of length encoding shall be used,
 * encoded in the minimum number of octets.
 * [Contrast with 8.1.3.2 b).]
 *
 *
 * **10.2 String encoding forms**
 * For BIT STRING, OCTET STRING and restricted character string types,
 * the constructed form of encoding shall not be used.
 * (Contrast with 8.21.6.)
 */
abstract class ASN1OctetString internal constructor(string: ByteArray) : ASN1Primitive() {
    /**
     * Return the content of the OCTET STRING as a byte array.
     *
     * @return the byte[] representing the OCTET STRING's content.
     */
    var octets: ByteArray = string


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1OctetString) {
            return false
        }

        return areArraysEqual(octets, other.octets)
    }

    override fun toDERObject(): ASN1Primitive {
        return DEROctetString(octets)
    }

    override fun toDLObject(): ASN1Primitive {
        return DEROctetString(octets)
    }
}
