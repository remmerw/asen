package io.github.remmerw.asen.cert

/**
 * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
 * a [] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
abstract class ASN1TaggedObject internal constructor(
    explicitness: Int,
    tagClass: Int,
    tagNo: Int,
    obj: ASN1Encodable
) :
    ASN1Primitive() {
    val tagClass: Int

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    val tagNo: Int
    val obj: ASN1Encodable
    private val explicitness: Int

    /**
     * Create a tagged object with the style given by the value of explicit.
     *
     *
     * If the object implements ASN1Choice the tag style will always be changed
     * to explicit in accordance with the ASN.1 encoding rules.
     *
     *
     * @param explicit true if the object is explicitly tagged.
     * @param tagNo    the tag number for this object.
     * @param obj      the tagged object.
     */
    internal constructor(
        explicit: Boolean,
        tagNo: Int,
        obj: ASN1Encodable
    ) : this(
        if (explicit) DECLARED_EXPLICIT else DECLARED_IMPLICIT,
        BERTags.CONTEXT_SPECIFIC,
        tagNo,
        obj
    )

    init {
        require(tagClass != BERTags.UNIVERSAL) { "invalid tag class: $tagClass" }

        this.explicitness = if ((obj is ASN1Choice)) DECLARED_EXPLICIT else explicitness
        this.tagClass = tagClass
        this.tagNo = tagNo
        this.obj = obj
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1TaggedObject) {
            return false
        }

        if (this.tagNo != other.tagNo ||
            this.tagClass != other.tagClass
        ) {
            return false
        }

        if (this.explicitness != other.explicitness) {
            if (this.isExplicit != other.isExplicit) {
                return false
            }
        }

        val p1 = obj.toASN1Primitive()
        val p2 = other.obj.toASN1Primitive()

        if (p1 === p2) {
            return true
        }

        if (!this.isExplicit) {
            try {
                val d1 = this.encoded()
                val d2 = other.encoded()

                return areArraysEqual(d1, d2)
            } catch (_: Exception) {
                return false
            }
        }

        return p1.asn1Equals(p2)
    }

    val isExplicit: Boolean
        /**
         * return whether or not the object may be explicitly tagged.
         *
         *
         * Note: if the object has been read from an input stream, the only
         * time you can be sure if isExplicit is returning the true state of
         * affairs is if it returns false. An implicitly tagged object may appear
         * to be explicitly tagged, so you need to understand the context under
         * which the reading was done as well, see getObject below.
         */
        get() = explicitness == DECLARED_EXPLICIT


    fun getBaseUniversal(): ASN1Primitive {

        check(isExplicit) { "object explicit - implicit expected." }

        return obj.toASN1Primitive()
    }


    override fun toDERObject(): ASN1Primitive {
        return DERTaggedObject(explicitness, tagClass, tagNo, obj)
    }
}
