package io.github.remmerw.asen.cert

internal class BERBitString(private val elements: Array<ASN1BitString>) : ASN1BitString(
    flattenBitStrings(
        elements
    )
) {

    override fun encodeConstructed(): Boolean {
        return true
    }


    override fun encodedLength(withTag: Boolean): Int {
        if (!encodeConstructed()) {
            return encodedLength(withTag, contents.size)
        }

        var totalLength = if (withTag) 4 else 3

        for (element in elements) {
            totalLength += element.encodedLength(true)
        } //  else case No bits


        return totalLength
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        if (!encodeConstructed()) {
            encode(out, withTag, contents, contents.size)
            return
        }

        out.writeIdentifier(withTag, BERTags.CONSTRUCTED or BERTags.BIT_STRING)
        out.write(0x80)

        out.writeBitPrimitives(elements) //  else case No bits


        out.write(0x00)
        out.write(0x00)
    }

}

