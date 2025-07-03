package io.github.remmerw.asen.cert

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * Class representing the ASN.1 OBJECT IDENTIFIER payloadType.
 */
class ASN1ObjectIdentifier : ASN1Primitive {
    /**
     * Return the OID as a string.
     *
     * @return the string representation of the OID carried by this object.
     */
    val id: String
    private val contents: ByteArray

    private constructor(contents: ByteArray) {
        val objId = StringBuilder()
        var value = 0L

        var first = true

        for (i in contents.indices) {
            val b = contents[i].toInt() and 0xff

            require(value <= LONG_LIMIT) { "out of supported range" }
            value += (b and 0x7F).toLong()
            if ((b and 0x80) == 0) {
                if (first) {
                    if (value < 40) {
                        objId.append('0')
                    } else if (value < 80) {
                        objId.append('1')
                        value -= 40
                    } else {
                        objId.append('2')
                        value -= 80
                    }
                    first = false
                }

                objId.append('.')
                objId.append(value)
                value = 0
            } else {
                value = value shl 7
            }
        }

        this.id = objId.toString()
        this.contents = contents.copyOf()
    }

    /**
     * Create an OID based on the passed in String.
     *
     * @param identifier a string representation of an OID.
     */
    constructor(identifier: String) {
        require(isValidIdentifier(identifier)) { "string $identifier not an OID" }

        this.id = identifier
        val bOut = Buffer()

        doOutput(bOut)

        contents = bOut.readByteArray()
    }

    /**
     * Create an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     */
    private constructor(
        oid: ASN1ObjectIdentifier,
        branchID: String
    ) : this(oid.id + "." + branchID) {
        require(isValidIdentifier(branchID, 0)) { "string $branchID not a valid OID branch" }
    }


    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    fun branch(branchID: String): ASN1ObjectIdentifier {
        return ASN1ObjectIdentifier(this, branchID)
    }

    private fun doOutput(aOut: Buffer) {
        val tok = OIDTokenizer(id)
        val first = checkNotNull(tok.nextToken()).toInt() * 40

        val secondToken = tok.nextToken()
        checkNotNull(secondToken)
        require(secondToken.length <= 18) { "out of supported range" }
        writeField(aOut, first + secondToken.toLong())

        while (tok.hasMoreTokens()) {
            val token = tok.nextToken()
            checkNotNull(token)
            require(token.length <= 18) { "out of supported range" }
            writeField(aOut, token.toLong())
        }
    }

    override fun encodeConstructed(): Boolean {
        return false
    }

    override fun encodedLength(withTag: Boolean): Int {
        return getLengthOfEncodingDL(withTag, contents.size)
    }


    override fun encode(out: ASN1OutputStream, withTag: Boolean) {
        out.writeEncodingDL(withTag, BERTags.OBJECT_IDENTIFIER, contents)
    }

    override fun hashCode(): Int {
        return id.hashCode() // ok
    }

    override fun asn1Equals(other: ASN1Primitive): Boolean {
        if (other === this) {
            return true
        }

        if (other !is ASN1ObjectIdentifier) {
            return false
        }

        return id == other.id
    }

    /**
     * Intern will return a reference to a pooled version of this object, unless it
     * is not present in which case intern will add it.
     *
     *
     * The pool is also used by the ASN.1 parsers to limit the number of duplicated OID
     * objects in circulation.
     *
     *
     * @return a reference to the identifier in the pool.
     */
    fun intern(): ASN1ObjectIdentifier {
        val hdl = OidHandle.create(contents)
        return pool.getOrPut(hdl) { this }
    }


    private data class OidHandle(val key: Int, val contents: ByteArray) {
        override fun hashCode(): Int {
            return key // ok
        }

        override fun equals(other: Any?): Boolean {
            if (other is OidHandle) {
                return areArraysEqual(contents, other.contents)
            }

            return false
        }

        companion object {
            fun create(contents: ByteArray): OidHandle {
                return OidHandle(hashArrayCode(contents), contents)
            }
        }
    }

    companion object {
        private const val LONG_LIMIT = (Long.MAX_VALUE shr 7) - 0x7F
        private val pool: MutableMap<OidHandle, ASN1ObjectIdentifier> = mutableMapOf()

        private fun isValidIdentifier(
            identifier: String
        ): Boolean {
            if (identifier.length < 3 || identifier[1] != '.') {
                return false
            }

            val first = identifier[0]
            if (first < '0' || first > '2') {
                return false
            }

            return isValidIdentifier(identifier, 2)
        }

        fun createPrimitive(contents: ByteArray): ASN1ObjectIdentifier {
            val hdl = OidHandle.create(contents)
            val oid = pool[hdl] ?: return ASN1ObjectIdentifier(
                contents
            )
            return oid
        }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        if (!super.equals(other)) return false

        other as ASN1ObjectIdentifier

        if (id != other.id) return false
        if (!contents.contentEquals(other.contents)) return false

        return true
    }
}
