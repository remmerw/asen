package io.github.remmerw.asen.cert


/**
 * <pre>
 * Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension         ::=   SEQUENCE {
 * extnId            EXTENSION.&amp;id ({ExtensionSet}),
 * critical          BOOLEAN DEFAULT FALSE,
 * extnValue         OCTET STRING }
</pre> *
 */
class Extensions : ASN1Object {
    private val extensions = HashMap<ASN1ObjectIdentifier, Extension>()
    private val ordering = mutableListOf<ASN1ObjectIdentifier>()

    /**
     * Constructor from ASN1Sequence.
     *
     *
     * The extensions are a list of constructed sequences, either with (OID, OctetString) or (OID, Boolean, OctetString)
     *
     */
    private constructor(seq: ASN1Sequence) {
        val array = seq.toArrayInternal()
        for (element in array) {
            val ext = Extension.getInstance(element)
            checkNotNull(ext)
            require(!extensions.containsKey(ext.extnId)) { "repeated extension found: " + ext.extnId }

            extensions[ext.extnId as ASN1ObjectIdentifier] = ext
            ordering.add(ext.extnId)
        }
    }

    /**
     * Base Constructor
     *
     * @param extensions an array of extensions.
     */
    internal constructor(extensions: Array<Extension>) {
        for (i in extensions.indices) {
            val ext = extensions[i]
            this.extensions[ext.extnId as ASN1ObjectIdentifier] = ext
            ordering.add(ext.extnId)
        }
    }

    /**
     * <pre>
     * Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension         ::=   SEQUENCE {
     * extnId            EXTENSION.&amp;id ({ExtensionSet}),
     * critical          BOOLEAN DEFAULT FALSE,
     * extnValue         OCTET STRING }
    </pre> *
     */
    override fun toASN1Primitive(): ASN1Primitive {
        val vec = ASN1EncodableVector()

        ordering.forEach { oid ->
            val ext = extensions[oid]
            vec.add(ext!!)
        }

        return DERSequence(vec)
    }

    companion object {
        fun getInstance(obj: Any?): Extensions? {
            if (obj is Extensions) {
                return obj
            } else if (obj != null) {
                return Extensions(getSequenceInstance(obj))
            }

            return null
        }
    }
}
