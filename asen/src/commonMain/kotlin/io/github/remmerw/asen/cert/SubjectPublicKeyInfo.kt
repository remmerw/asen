package io.github.remmerw.asen.cert

/**
 * The object that contains the public key stored in a certificate.
 *
 *
 * The getEncoded() method in the public keys in the JCE produces a DER
 * encoded one of these.
 */
class SubjectPublicKeyInfo private constructor(seq: ASN1Sequence) : ASN1Object() {
    private val algId: AlgorithmIdentifier?
    private val keyData: ASN1BitString?

    init {
        require(seq.size() == 2) {
            ("Bad sequence size: "
                    + seq.size())
        }


        val e = seq.toArrayInternal()

        this.algId = AlgorithmIdentifier.getInstance(e[0])
        this.keyData = getASN1BitStringInstance(e[1])
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     * algorithm AlgorithmIdentifier,
     * publicKey BIT STRING }
    </pre> *
     */
    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector()

        v.add(algId!!)
        v.add(keyData!!)

        return DERSequence(v)
    }

    companion object {

        fun getInstance(obj: Any?): SubjectPublicKeyInfo {
            if (obj is SubjectPublicKeyInfo) {
                return obj
            } else if (obj != null) {
                return SubjectPublicKeyInfo(getSequenceInstance(obj))
            }
            throw RuntimeException()
        }
    }
}
