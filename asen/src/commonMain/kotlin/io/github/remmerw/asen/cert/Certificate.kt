package io.github.remmerw.asen.cert


/**
 * an X509Certificate structure.
 * <pre>
 * Certificate ::= SEQUENCE {
 * tbsCertificate          TBSCertificate,
 * signatureAlgorithm      AlgorithmIdentifier,
 * signature               BIT STRING
 * }
</pre> *
 */
class Certificate private constructor(private val seq: ASN1Sequence) : ASN1Object() {
    init {
        //
        // correct x509 certificate
        //
        if (seq.size() == 3) {
            TBSCertificate.getInstance(seq.getObjectAt(0))
            val sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1))
            checkNotNull(sigAlgId)
            getASN1BitStringInstance(seq.getObjectAt(2))
        } else {
            throw IllegalArgumentException("sequence wrong size for a certificate")
        }
    }

    override fun toASN1Primitive(): ASN1Primitive {
        return seq
    }

    companion object {
        fun getInstance(obj: Any?): Certificate {
            if (obj is Certificate) {
                return obj
            } else if (obj != null) {
                return Certificate(getSequenceInstance(obj))
            }
            throw RuntimeException()
        }
    }
}
