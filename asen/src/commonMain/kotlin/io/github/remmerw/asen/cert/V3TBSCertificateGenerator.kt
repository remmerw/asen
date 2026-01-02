package io.github.remmerw.asen.cert

/**
 * Generator for Version 3 TBSCertificateStructures.
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
 */
class V3TBSCertificateGenerator {
    private val version = DERTaggedObject(true, 0, ASN1Integer(2))

    private var serialNumber: ASN1Integer? = null
    private var signature: AlgorithmIdentifier? = null
    private var issuer: X500Name? = null
    private var startDate: Time? = null
    private var endDate: Time? = null
    private var subject: X500Name? = null
    private var subjectPublicKeyInfo: SubjectPublicKeyInfo? = null
    private var extensions: Extensions? = null


    fun setSerialNumber(serialNumber: ASN1Integer?) {
        this.serialNumber = serialNumber
    }

    fun setSignature(signature: AlgorithmIdentifier?) {
        this.signature = signature
    }

    fun setIssuer(issuer: X500Name?) {
        this.issuer = issuer
    }

    fun setStartDate(startDate: Time?) {
        this.startDate = startDate
    }

    fun setEndDate(endDate: Time?) {
        this.endDate = endDate
    }

    fun setSubject(subject: X500Name?) {
        this.subject = subject
    }

    fun setSubjectPublicKeyInfo(pubKeyInfo: SubjectPublicKeyInfo?) {
        this.subjectPublicKeyInfo = pubKeyInfo
    }

    fun setExtensions(extensions: Extensions?) {
        this.extensions = extensions
    }

    fun generateTBSCertificate(): TBSCertificate {
        check(
            !((serialNumber == null) || (signature == null)
                    || (issuer == null) || (startDate == null) || (endDate == null)
                    || (subjectPublicKeyInfo == null))
        ) { "not all mandatory fields set in V3 TBSCertificate generator" }

        val v = ASN1EncodableVector()

        v.add(version)
        v.add(serialNumber!!)
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
            v.add(subject!!)
        } else {
            v.add(DERSequence())
        }

        v.add(subjectPublicKeyInfo!!)


        if (extensions != null) {
            v.add(DERTaggedObject(true, 3, extensions!!))
        }

        return TBSCertificate.getInstance(DERSequence(v))
    }
}
