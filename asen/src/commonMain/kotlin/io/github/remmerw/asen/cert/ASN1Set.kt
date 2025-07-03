package io.github.remmerw.asen.cert

import kotlin.math.min

/**
 * ASN.1 `SET` and `SET OF` constructs.
 *
 *
 * Note: This does not know which syntax the set is!
 * (The difference: ordering of SET elements or not ordering.)
 *
 *
 * DER form is always definite form length fields, while
 * BER support uses indefinite form.
 *
 *
 * The CER form support does not exist.
 *
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.11 Encoding of a set value </h4>
 * **8.11.1** The encoding of a set value shall be constructed
 *
 *
 * **8.11.2** The contents octets shall consist of the complete
 * encoding of a data value from each of the types listed in the
 * ASN.1 definition of the set payloadType, in an order chosen by the sender,
 * unless the payloadType was referenced with the keyword
 * **OPTIONAL** or the keyword **DEFAULT**.
 *
 *
 * **8.11.3** The encoding of a data value may, but need not,
 * be present for a payloadType which was referenced with the keyword
 * **OPTIONAL** or the keyword **DEFAULT**.
 * <blockquote>
 * NOTE  The order of data values in a set value is not significant,
 * and places no constraints on the order during transfer
</blockquote> *
 * <h4>8.12 Encoding of a set-of value</h4>
 *
 *
 * **8.12.1** The encoding of a set-of value shall be constructed.
 *
 *
 * **8.12.2** The text of 8.10.2 applies:
 * *The contents octets shall consist of zero,
 * one or more complete encodings of data values from the payloadType listed in
 * the ASN.1 definition.*
 *
 *
 * **8.12.3** The order of data values need not be preserved by
 * the encoding and subsequent decoding.
 *
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.1 Length forms</h4>
 * If the encoding is constructed, it shall employ the indefinite-length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 * <h4>9.3 Set components</h4>
 * The encodings of the component values of a set value shall
 * appear in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * Additionally, for the purposes of determining the order in which
 * components are encoded when one or more component is an untagged
 * choice payloadType, each untagged choice payloadType is ordered as though it
 * has a tag equal to that of the smallest tag in that choice payloadType
 * or any untagged choice types nested within.
 *
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.1 Length forms</h4>
 * The definite form of length encoding shall be used,
 * encoded in the minimum number of octets.
 * [Contrast with 8.1.3.2 b).]
 * <h4>10.3 Set components</h4>
 * The encodings of the component values of a set value shall appear
 * in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <blockquote>
 * NOTE  Where a component of the set is an untagged choice payloadType,
 * the location of that component in the ordering will depend on
 * the tag of the choice component being encoded.
</blockquote> *
 *
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.5 Set and sequence components with default value </h4>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 * <h4>11.6 Set-of components </h4>
 *
 *
 * The encodings of the component values of a set-of value
 * shall appear in ascending order, the encodings being compared
 * as octet strings with the shorter components being padded at
 * their trailing end with 0-octets.
 * <blockquote>
 * NOTE  The padding octets are for comparison purposes only
 * and do not appear in the encodings.
</blockquote> *
 */
abstract class ASN1Set : ASN1Primitive {
    val elements: Array<ASN1Encodable>
    val isSorted: Boolean

    internal constructor() {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS
        this.isSorted = true
    }

    /**
     * Create a SET containing one object
     *
     * @param element object to be added to the SET.
     */
    internal constructor(element: ASN1Encodable) {
        this.elements = arrayOf(element)
        this.isSorted = true
    }

    /**
     * Create a SET containing a vector of objects.
     *
     * @param elementVector a vector of objects to make up the SET.
     */
    internal constructor(elementVector: ASN1EncodableVector) {
        val tmp = elementVector.takeElements()
        this.elements = tmp
        this.isSorted = tmp.size < 2
    }

    /**
     * Create a SET containing an array of objects.
     *
     * @param elements an array of objects to make up the SET.
     */
    internal constructor(elements: Array<ASN1Encodable>) {

        val tmp = elements.copyOf()
        if (tmp.size >= 2) {
            sort(tmp)
        }

        this.elements = tmp
        this.isSorted = true
    }


    /**
     * return the number of objects in this set.
     *
     * @return the number of objects in this set.
     */
    fun size(): Int {
        return elements.size
    }


    /**
     * Change current SET object to be encoded as [DERSet].
     * This is part of Distinguished Encoding Rules form serialization.
     */
    override fun toDERObject(): ASN1Primitive {
        val tmp: Array<ASN1Encodable>
        if (isSorted) {
            tmp = elements
        } else {
            tmp = elements.copyOf()
            sort(tmp)
        }

        return DERSet(tmp)
    }


    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other !is ASN1Set) {
            return false
        }

        val count = this.size()
        if (other.size() != count) {
            return false
        }

        val dis = toDERObject() as DERSet
        val dat = other.toDERObject() as DERSet

        for (i in 0 until count) {
            val p1 = dis.elements[i].toASN1Primitive()
            val p2 = dat.elements[i].toASN1Primitive()

            if (p1 !== p2 && !p1.asn1Equals(p2)) {
                return false
            }
        }

        return true
    }

    override fun encodeConstructed(): Boolean {
        return true
    }


    override fun toString(): String {
        val count = size()
        if (0 == count) {
            return "[]"
        }

        val sb = StringBuilder()
        sb.append('[')
        var i = 0
        while (true) {
            sb.append(elements[i])
            if (++i >= count) {
                break
            }
            sb.append(", ")
        }
        sb.append(']')
        return sb.toString()
    }


    private fun getDEREncoded(obj: ASN1Encodable): ByteArray {
        return obj.toASN1Primitive().getEncoded(DER)
    }

    /**
     * return true if a <= b (arrays are assumed padded with zeros).
     */
    private fun lessThanOrEqual(a: ByteArray, b: ByteArray): Boolean {
//        assert a.length >= 2 && b.length >= 2;

        /*
     * NOTE: Set elements in DER encodings are ordered first according to their tags (class and
     * number); the CONSTRUCTED bit is not part of the tag.
     *
     * For SET-OF, this is unimportant. All elements have the same tag and DER requires them to
     * either all be in constructed form or all in primitive form, according to that tag. The
     * elements are effectively ordered according to their content octets.
     *
     * For SET, the elements will have distinct tags, and each will be in constructed or
     * primitive form accordingly. Failing to ignore the CONSTRUCTED bit could therefore lead to
     * ordering inversions.
     */

        val a0 = a[0].toInt() and BERTags.CONSTRUCTED.inv()
        val b0 = b[0].toInt() and BERTags.CONSTRUCTED.inv()
        if (a0 != b0) {
            return a0 < b0
        }

        val last = (min(a.size, b.size) - 1)
        for (i in 1 until last) {
            if (a[i] != b[i]) {
                return (a[i].toInt() and 0xFF) < (b[i].toInt() and 0xFF)
            }
        }
        return (a[last].toInt() and 0xFF) <= (b[last].toInt() and 0xFF)
    }

    private fun sort(t: Array<ASN1Encodable>) {
        val count = t.size
        if (count < 2) {
            return
        }

        var eh = t[0]
        var ei = t[1]
        var bh = getDEREncoded(eh)
        var bi = getDEREncoded(ei)

        if (lessThanOrEqual(bi, bh)) {
            val et = ei
            ei = eh
            eh = et
            val bt = bi
            bi = bh
            bh = bt
        }

        for (i in 2 until count) {
            val e2 = t[i]
            val b2 = getDEREncoded(e2)

            if (lessThanOrEqual(bi, b2)) {
                t[i - 2] = eh
                eh = ei
                bh = bi
                ei = e2
                bi = b2
                continue
            }

            if (lessThanOrEqual(bh, b2)) {
                t[i - 2] = eh
                eh = e2
                bh = b2
                continue
            }

            var j = i - 1
            while (--j > 0) {
                val e1 = t[j - 1]
                val b1 = getDEREncoded(e1)

                if (lessThanOrEqual(b1, b2)) {
                    break
                }

                t[j] = e1
            }

            t[j] = e2
        }

        t[count - 2] = eh
        t[count - 1] = ei
    }

}
