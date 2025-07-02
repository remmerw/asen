package io.github.remmerw.asen.cert

class ASN1ObjectDescriptor private constructor(private val baseGraphicString: ASN1GraphicString) :
    ASN1Primitive() {

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return baseGraphicString.encodedLength(withTag)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeIdentifier(withTag, BERTags.OBJECT_DESCRIPTOR)
        baseGraphicString.encode(out, false)
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1ObjectDescriptor) {
            return false
        }

        return baseGraphicString.asn1Equals(other.baseGraphicString)
    }

    companion object {

        fun createPrimitive(contents: ByteArray): ASN1ObjectDescriptor {
            return ASN1ObjectDescriptor(ASN1GraphicString.createPrimitive(contents))
        }
    }
}
