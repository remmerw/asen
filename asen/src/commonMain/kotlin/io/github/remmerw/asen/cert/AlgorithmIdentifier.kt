package io.github.remmerw.asen.cert

class AlgorithmIdentifier : ASN1Object {
    val algorithm: ASN1ObjectIdentifier
    private var parameters: ASN1Encodable? = null

    constructor(algorithm: ASN1ObjectIdentifier) {
        this.algorithm = algorithm
    }

    constructor(algorithm: ASN1ObjectIdentifier, parameters: ASN1Encodable?) {
        this.algorithm = algorithm
        this.parameters = parameters
    }

    private constructor(seq: ASN1Sequence) {
        require(!(seq.size() < 1 || seq.size() > 2)) {
            ("Bad sequence size: "
                    + seq.size())
        }

        algorithm = getASN1ObjectIdentifierInstance(seq.getObjectAt(0))

        parameters = if (seq.size() == 2) {
            seq.getObjectAt(1)
        } else {
            null
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * AlgorithmIdentifier ::= SEQUENCE {
     * algorithm OBJECT IDENTIFIER,
     * parameters ANY DEFINED BY algorithm OPTIONAL }
    </pre> *
     */
    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector()

        v.add(algorithm)

        if (parameters != null) {
            v.add(parameters!!)
        }

        return DERSequence(v)
    }

    companion object {
        fun getInstance(obj: Any?): AlgorithmIdentifier? {
            if (obj is AlgorithmIdentifier) {
                return obj
            } else if (obj != null) {
                return AlgorithmIdentifier(getSequenceInstance(obj))
            }

            return null
        }
    }
}
