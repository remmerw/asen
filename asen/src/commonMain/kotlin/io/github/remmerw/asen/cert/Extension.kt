package io.github.remmerw.asen.cert

/**
 * an object for the elements in the X.509 V3 extension block.
 */
class Extension : ASN1Object {
    val extnId: ASN1ObjectIdentifier?
    private val critical: Boolean
    val extnValue: ASN1OctetString?

    /**
     * Constructor using a byte[] for the value.
     *
     * @param extnId   the OID associated with this extension.
     * @param critical true if the extension is critical, false otherwise.
     * @param value    the extension's value as a byte[] to be wrapped in an OCTET STRING.
     */
    internal constructor(
        extnId: ASN1ObjectIdentifier?,
        critical: Boolean,
        value: ByteArray
    ) : this(
        extnId, critical, DEROctetString(
            value.copyOf()
        )
    )

    /**
     * Constructor using an OCTET STRING for the value.
     *
     * @param extnId   the OID associated with this extension.
     * @param critical true if the extension is critical, false otherwise.
     * @param value    the extension's value wrapped in an OCTET STRING.
     */
    internal constructor(
        extnId: ASN1ObjectIdentifier?,
        critical: Boolean,
        value: ASN1OctetString?
    ) {
        this.extnId = extnId
        this.critical = critical
        this.extnValue = value
    }

    private constructor(seq: ASN1Sequence) {
        if (seq.size() == 2) {
            this.extnId = getASN1ObjectIdentifierInstance(seq.getObjectAt(0))
            this.critical = false
            this.extnValue = getASN1OctetStringInstance(seq.getObjectAt(1))
        } else if (seq.size() == 3) {
            this.extnId = getASN1ObjectIdentifierInstance(seq.getObjectAt(0))
            this.critical = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue
            this.extnValue = getASN1OctetStringInstance(seq.getObjectAt(2))
        } else {
            throw IllegalArgumentException("Bad sequence size: " + seq.size())
        }
    }


    override fun equals(
        other: Any?
    ): Boolean {
        if (other !is Extension) {
            return false
        }

        return other.extnId!! == this.extnId
                && other.extnValue!! == this.extnValue
                && (other.critical == this.critical)
    }

    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector()

        v.add(extnId!!)

        if (critical) {
            v.add(ASN1Boolean.getInstance(true))
        }

        v.add(extnValue!!)

        return DERSequence(v)
    }

    override fun hashCode(): Int {
        var result = extnId?.hashCode() ?: 0
        result = 31 * result + critical.hashCode()
        result = 31 * result + (extnValue?.hashCode() ?: 0)
        return result
    }

    companion object {
        /**
         * Subject Directory Attributes
         */
        val subjectDirectoryAttributes: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("2.5.29.9").intern()

        /**
         * Subject Alternative Name
         */
        val subjectAlternativeName: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("2.5.29.17").intern()

        /**
         * Issuer Alternative Name
         */
        val issuerAlternativeName: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.29.18").intern()

        /**
         * Certificate Issuer
         */
        val certificateIssuer: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.29.29").intern()

        fun getInstance(obj: Any?): Extension? {
            if (obj is Extension) {
                return obj
            } else if (obj != null) {
                return Extension(getSequenceInstance(obj))
            }

            return null
        }
    }
}
