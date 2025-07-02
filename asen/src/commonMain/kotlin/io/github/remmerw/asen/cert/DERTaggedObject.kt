package io.github.remmerw.asen.cert


/**
 * DER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
class DERTaggedObject : ASN1TaggedObject {
    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo    the tag number for this object.
     * @param obj      the tagged object.
     */
    constructor(explicit: Boolean, tagNo: Int, obj: ASN1Encodable) : super(explicit, tagNo, obj)

    internal constructor(explicitness: Int, tagClass: Int, tagNo: Int, obj: ASN1Encodable) : super(
        explicitness,
        tagClass,
        tagNo,
        obj
    )

    override fun encodeConstructed(): Boolean {
        return isExplicit || obj.toASN1Primitive().toDERObject().encodeConstructed()
    }


    override fun encodedLength(withTag: Boolean): Int {
        val primitive = obj.toASN1Primitive().toDERObject()
        val explicit = isExplicit

        var length = primitive.encodedLength(explicit)

        if (explicit) {
            length += getLengthOfDL(length)
        }

        length += if (withTag) getLengthOfIdentifier(tagNo) else 0

        return length
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {

        val primitive = obj.toASN1Primitive().toDERObject()
        val explicit = isExplicit

        if (withTag) {
            var flags = tagClass
            if (explicit || primitive.encodeConstructed()) {
                flags = flags or BERTags.CONSTRUCTED
            }

            out.writeIdentifier(flags, tagNo)
        }

        if (explicit) {
            out.writeDL(primitive.encodedLength(true))
        }

        primitive.encode(out.dERSubStream(), explicit)
    }

    override fun toDERObject(): ASN1Primitive {
        return this
    }
}
