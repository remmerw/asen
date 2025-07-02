package io.github.remmerw.asen.cert


/**
 * Generator for X.509 extensions
 */
class ExtensionsGenerator {
    private val extensions = HashMap<ASN1ObjectIdentifier, Extension>()
    private val extOrdering = mutableListOf<ASN1ObjectIdentifier>()

    /**
     * Add an extension with the given oid and the passed in value to be included
     * in the OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the ASN.1 object to be included in the extension.
     */

    fun addExtension(
        oid: ASN1ObjectIdentifier,
        critical: Boolean,
        value: ASN1Encodable
    ) {
        this.addExtension(oid, critical, value.toASN1Primitive().getEncoded(DER))
    }

    /**
     * Add an extension with the given oid and the passed in byte array to be wrapped in the
     * OCTET STRING associated with the extension.
     *
     * @param oid      OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value    the byte array to be wrapped.
     */
    private fun addExtension(
        oid: ASN1ObjectIdentifier,
        critical: Boolean,
        value: ByteArray
    ) {
        if (extensions.containsKey(oid)) {
            if (dupsAllowed.contains(oid)) {
                val existingExtension = extensions[oid]
                val seq1 = getSequenceInstance(
                    getASN1OctetStringInstance(checkNotNull(existingExtension).extnValue!!).octets
                )
                val seq2 = getSequenceInstance(value)

                val items = ASN1EncodableVector()

                for (element in seq1.toArrayInternal()) {
                    items.add(element)
                }
                for (element in seq2.toArrayInternal()) {
                    items.add(element)
                }


                extensions[oid] =
                    Extension(oid, critical, DERSequence(items).encoded())

            } else {
                throw IllegalArgumentException("extension $oid already added")
            }
        } else {
            extOrdering.add(oid)
            extensions[oid] = Extension(
                oid, critical,
                DEROctetString(cloneArray(value))
            )
        }
    }

    val isEmpty: Boolean
        /**
         * Return true if there are no extension present in this generator.
         *
         * @return true if empty, false otherwise
         */
        get() = extOrdering.isEmpty()

    /**
     * Generate an Extensions object based on the current state of the generator.
     *
     * @return an X09Extensions object.
     */
    fun generate(): Extensions {
        val exts = mutableListOf<Extension>()

        for (i in extOrdering.indices) {
            exts.add(i, extensions[extOrdering.elementAt(i)]!!)
        }

        return Extensions(exts.toTypedArray())
    }


    private val dupsAllowed: Set<ASN1ObjectIdentifier> =
        setOf(
            Extension.subjectAlternativeName,
            Extension.issuerAlternativeName,
            Extension.subjectDirectoryAttributes,
            Extension.certificateIssuer
        )

}
