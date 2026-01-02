package io.github.remmerw.asen.cert

/**
 * The TBSCertificate object.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 * version          [ 0 ]  Version DEFAULT v1(0),
 * serialNumber            CertificateSerialNumber,
 * signature               AlgorithmIdentifier,
 * issuer                  Name,
 * validity                Validity,
 * subject                 Name,
 * subjectPublicKeyInfo    SubjectPublicKeyInfo,
 * issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 * subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 * extensions        [ 3 ] Extensions OPTIONAL
 * }
</pre> *
 *
 *
 * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
 * will parse them, but you really shouldn't be creating new ones.
 */
class TBSCertificate private constructor(seq: ASN1Sequence) : ASN1Object() {
    private var version: ASN1Integer? = null
    private val serialNumber: ASN1Integer
    private val signature: AlgorithmIdentifier?
    private val issuer: X500Name?
    private val startDate: Time?
    private val endDate: Time?
    private val subject: X500Name?
    private val subjectPublicKeyInfo: SubjectPublicKeyInfo?
    private var issuerUniqueId: ASN1BitString? = null
    private var subjectUniqueId: ASN1BitString? = null
    private var extensions: Extensions? = null

    init {
        var seqStart = 0

        //
        // some certificates don't include a version number - we assume v1
        //
        if (seq.getObjectAt(0) is ASN1TaggedObject) {
            version = ASN1Integer.getInstance(seq.getObjectAt(0) as ASN1TaggedObject)
        } else {
            seqStart = -1 // field 0 is missing!
            version = ASN1Integer(0)
        }

        var isV1 = false
        var isV2 = false

        if (version!!.hasValue(0)) {
            isV1 = true
        } else if (version!!.hasValue(1)) {
            isV2 = true
        } else require(version!!.hasValue(2)) { "version number not recognised" }

        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(seqStart + 1))

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqStart + 2))
        issuer = X500Name.getInstance(seq.getObjectAt(seqStart + 3))

        //
        // before and after dates
        //
        val dates = seq.getObjectAt(seqStart + 4) as ASN1Sequence

        startDate = getTimeInstance(dates.getObjectAt(0))
        endDate = getTimeInstance(dates.getObjectAt(1))

        subject = X500Name.getInstance(seq.getObjectAt(seqStart + 5))

        //
        // public key info.
        //
        subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(seqStart + 6))

        var extras = seq.size() - (seqStart + 6) - 1
        require(!(extras != 0 && isV1)) { "version 1 certificate contains extra data" }

        while (extras > 0) {
            val extra = seq.getObjectAt(seqStart + 6 + extras) as ASN1TaggedObject

            when (extra.tagNo) {
                3 -> {
                    require(!isV2) { "version 2 certificate cannot contain extensions" }
                    extensions = Extensions.getInstance(ASN1Sequence.getInstance(extra))
                }

                else -> throw IllegalArgumentException("Unknown tag encountered in structure: " + extra.tagNo)
            }
            extras--
        }
    }

    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector()

        // DEFAULT Zero
        if (!version!!.hasValue(0)) {
            v.add(DERTaggedObject(true, 0, version!!))
        }

        v.add(serialNumber)
        v.add(signature!!)
        v.add(issuer!!)

        //
        // before and after dates
        //
        run {
            val validity = ASN1EncodableVector()
            validity.add(startDate!!)
            validity.add(endDate!!)
            v.add(DERSequence(validity))
        }


        if (subject != null) {
            v.add(subject)
        } else {
            v.add(DERSequence())
        }

        v.add(subjectPublicKeyInfo!!)

        // Note: implicit tag
        if (issuerUniqueId != null) {
            v.add(DERTaggedObject(false, 1, issuerUniqueId!!))
        }

        // Note: implicit tag
        if (subjectUniqueId != null) {
            v.add(DERTaggedObject(false, 2, subjectUniqueId!!))
        }

        if (extensions != null) {
            v.add(DERTaggedObject(true, 3, extensions!!))
        }

        return DERSequence(v)
    }

    companion object {
        fun getInstance(obj: Any?): TBSCertificate {
            if (obj is TBSCertificate) {
                return obj
            } else if (obj != null) {
                return TBSCertificate(getSequenceInstance(obj))
            }
            throw RuntimeException()
        }
    }
}
