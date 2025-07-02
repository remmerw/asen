package io.github.remmerw.asen.cert

/**
 * ASN.1 OctetStrings, with indefinite length rules, and *constructed form* support.
 *
 *
 * The Basic Encoding Rules (BER) format allows encoding using so called "*constructed form*",
 * which DER and CER formats forbid allowing only "primitive form".
 *
 *
 * This class **always** produces the constructed form with underlying segments
 * in an indefinite length array.  If the input wasn't the same, then this output
 * is not faithful reproduction.
 *
 *
 *
 * See [ASN1OctetString] for X.690 encoding rules of OCTET-STRING objects.
 *
 */
internal class BEROctetString(private val elements: Array<ASN1OctetString>) : ASN1OctetString(
    flattenOctetStrings(
        elements
    )
) {

    override fun encodeConstructed(): Boolean {
        return true
    }


    override fun encodedLength(withTag: Boolean): Int {
        if (!encodeConstructed()) {
            return DEROctetString.encodedLength(withTag, octets.size)
        }

        var totalLength = if (withTag) 4 else 3

        for (element in elements) {
            totalLength += element.encodedLength(true)
        }

        return totalLength
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        if (!encodeConstructed()) {
            DEROctetString.encode(out, withTag, octets, 0, octets.size)
            return
        }

        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.OCTET_STRING)
        out.write(0x80)

        out.writeOctetPrimitives(elements)

        out.write(0x00)
        out.write(0x00)
    }

}

