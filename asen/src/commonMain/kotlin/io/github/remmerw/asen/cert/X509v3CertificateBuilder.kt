package io.github.remmerw.asen.cert

import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.ECDSA.PrivateKey
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.bigint.BigInt
import kotlinx.datetime.LocalDateTime
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * class to produce an X.509 Version 3 certificate.
 */
class X509v3CertificateBuilder private constructor(
    issuer: X500Name, serial: BigInt, notBefore: Time,
    notAfter: Time, subject: X500Name,
    publicKeyInfo: SubjectPublicKeyInfo
) {
    private val tbsGen = V3TBSCertificateGenerator()
    private val extGenerator: ExtensionsGenerator

    /**
     * Create a builder for a version 3 certificate. You may need to use this constructor if the default locale
     * doesn't use a Gregorian calender so that the Time produced is compatible with other ASN.1 implementations.
     *
     * @param issuer        the certificate issuer
     * @param serial        the certificate serial number
     * @param notBefore     the date before which the certificate is not valid
     * @param notAfter      the date after which the certificate is not valid
     * @param subject       the certificate subject
     * @param publicKeyInfo the info structure for the public key to be associated with this certificate.
     */
    internal constructor(
        issuer: X500Name, serial: BigInt, notBefore: LocalDateTime,
        notAfter: LocalDateTime, subject: X500Name,
        publicKeyInfo: SubjectPublicKeyInfo
    ) : this(
        issuer, serial, Time(notBefore), Time(notAfter),
        subject, publicKeyInfo
    )


    init {
        tbsGen.setSerialNumber(ASN1Integer(serial))
        tbsGen.setIssuer(issuer)
        tbsGen.setStartDate(notBefore)
        tbsGen.setEndDate(notAfter)
        tbsGen.setSubject(subject)
        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo)

        extGenerator = ExtensionsGenerator()
    }

    /**
     * Add a given extension field for the standard extensions tag (tag 3)
     *
     * @param oid        the OID defining the extension payloadType.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value      the ASN.1 structure that forms the extension's value.
     * @return this builder object.
     */
    fun addExtension(
        oid: ASN1ObjectIdentifier, isCritical: Boolean,
        value: ASN1Encodable
    ): X509v3CertificateBuilder {
        extGenerator.addExtension(oid, isCritical, value)
        return this
    }

    /**
     * Generate an X.509 certificate, based on the current issuer and subject
     * using the passed in signer.
     * @return a holder containing the resulting signed certificate.
     */
    fun build(signatureAlgorithm: String, privateKey: PrivateKey): Certificate {
        val sigAlgId = find(signatureAlgorithm)
        tbsGen.setSignature(sigAlgId)

        if (!extGenerator.isEmpty) {
            tbsGen.setExtensions(extGenerator.generate())
        }
        val tbsCert = tbsGen.generateTBSCertificate()
        return generateStructure(
            tbsCert, sigAlgId, generateSig(privateKey, tbsCert)

        )
    }


    private fun generateSig(privateKey: PrivateKey, tbsObj: ASN1Object): ByteArray {
        val sOut = Buffer()
        tbsObj.encodeTo(sOut, DER)
        return privateKey.signatureGenerator(digest = SHA256, format = ECDSA.SignatureFormat.RAW)
            .generateSignatureBlocking(sOut.readByteArray())

    }

    private fun generateStructure(
        tbsCert: TBSCertificate,
        sigAlgId: AlgorithmIdentifier,
        signature: ByteArray
    ): Certificate {
        val v = ASN1EncodableVector()

        v.add(tbsCert)
        v.add(sigAlgId)
        v.add(DERBitString(signature, 0))

        return Certificate.getInstance(DERSequence(v))
    }

}