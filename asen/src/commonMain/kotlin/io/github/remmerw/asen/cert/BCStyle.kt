package io.github.remmerw.asen.cert

class BCStyle private constructor() : AbstractX500NameStyle() {
    override fun encodeStringValue(oid: ASN1ObjectIdentifier, value: String): ASN1Encodable {
        if (oid.equals(EmailAddress) || oid.equals(DC)) {
            return DERIA5String(value)
        } else if (oid.equals(DATE_OF_BIRTH))  // accept time string as well as # (for compatibility)
        {
            return ASN1GeneralizedTime(value)
        } else if (oid.equals(C) || oid.equals(DN_QUALIFIER)
            || oid.equals(TELEPHONE_NUMBER)
        ) {
            return DERPrintableString(value)
        }

        return super.encodeStringValue(oid, value)
    }

    override fun attrNameToOID(attrName: String): ASN1ObjectIdentifier {
        return decodeAttrName(attrName, DefaultLookUp)
    }

    fun fromString(dirName: String): Array<ASN1Encodable> {
        return rDNsFromString(dirName, this)
    }


    companion object {
        /**
         * country code - StringType(SIZE(2))
         */
        private val C: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.6").intern()

        /**
         * organization - StringType(SIZE(1..64))
         */
        private val O: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.10").intern()

        /**
         * organizational unit name - StringType(SIZE(1..64))
         */
        private val OU: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.11").intern()

        /**
         * Title
         */
        private val T: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.12").intern()

        /**
         * common name - StringType(SIZE(1..64))
         */
        private val CN: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.3").intern()


        /**
         * street - StringType(SIZE(1..64))
         */
        private val STREET: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.9").intern()

        /**
         * device serial number name - StringType(SIZE(1..64))
         */
        private val SERIALNUMBER: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.5").intern()

        /**
         * locality name - StringType(SIZE(1..64))
         */
        private val L: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.7").intern()

        /**
         * state, or province name - StringType(SIZE(1..64))
         */
        private val ST: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.8").intern()

        /**
         * Naming attributes of payloadType X520name
         */
        private val SURNAME: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.4").intern()
        private val GIVENNAME: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.42").intern()
        private val INITIALS: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.43").intern()
        private val GENERATION: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.44").intern()
        private val UNIQUE_IDENTIFIER: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("2.5.4.45").intern()

        private val DESCRIPTION: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.13").intern()

        /**
         * businessCategory - DirectoryString(SIZE(1..128)
         */
        private val BUSINESS_CATEGORY: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("2.5.4.15").intern()

        /**
         * postalCode - DirectoryString(SIZE(1..40)
         */
        private val POSTAL_CODE: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.17").intern()

        /**
         * dnQualifier - DirectoryString(SIZE(1..64)
         */
        private val DN_QUALIFIER: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.46").intern()

        /**
         * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
         */
        private val PSEUDONYM: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.65").intern()

        private val ROLE: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.72").intern()

        /**
         * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
         */
        private val DATE_OF_BIRTH: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1").intern()

        /**
         * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
         */
        private val PLACE_OF_BIRTH: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2").intern()

        /**
         * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
         */
        private val GENDER: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3").intern()

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        private val COUNTRY_OF_CITIZENSHIP: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4").intern()

        /**
         * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        private val COUNTRY_OF_RESIDENCE: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5").intern()


        /**
         * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
         */
        private val NAME_AT_BIRTH: ASN1ObjectIdentifier =
            ASN1ObjectIdentifier("1.3.36.8.3.14").intern()

        /**
         * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
         * DirectoryString(SIZE(1..30))
         */
        private val POSTAL_ADDRESS: ASN1ObjectIdentifier = ASN1ObjectIdentifier("2.5.4.16").intern()

        /**
         * id-at-telephoneNumber
         */
        private val TELEPHONE_NUMBER = id_at_telephoneNumber

        /**
         * id-at-name
         */
        private val NAME = id_at_name


        /**
         * id-at-organizationIdentifier
         */
        private val ORGANIZATION_IDENTIFIER = id_at_organizationIdentifier

        /**
         * Email address (RSA PKCS#9 extension) - IA5String.
         *
         * Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
         */
        private val EmailAddress = pkcs_9_at_emailAddress

        /**
         * more from PKCS#9
         */
        private val UnstructuredName = pkcs_9_at_unstructuredName
        private val UnstructuredAddress = pkcs_9_at_unstructuredAddress

        /**
         * email address in Verisign certificates
         */
        private val E = EmailAddress

        /*
     * others...
     */
        private val DC = ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25")

        /**
         * LDAP User id.
         */
        private val UID = ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1")

        /**
         * look up table translating common symbols into their OIDS.
         */
        private val DefaultLookUp = HashMap<String, ASN1ObjectIdentifier>()

        /**
         * Singleton instance.
         */
        @Volatile
        private var INSTANCE: BCStyle? = null

        init {
            DefaultLookUp["c"] = C
            DefaultLookUp["o"] = O
            DefaultLookUp["t"] = T
            DefaultLookUp["ou"] = OU
            DefaultLookUp["cn"] = CN
            DefaultLookUp["l"] = L
            DefaultLookUp["st"] = ST
            DefaultLookUp["sn"] = SURNAME
            DefaultLookUp["serialnumber"] = SERIALNUMBER
            DefaultLookUp["street"] = STREET
            DefaultLookUp["emailaddress"] = E
            DefaultLookUp["dc"] = DC
            DefaultLookUp["e"] = E
            DefaultLookUp["uid"] = UID
            DefaultLookUp["surname"] = SURNAME
            DefaultLookUp["givenname"] = GIVENNAME
            DefaultLookUp["initials"] = INITIALS
            DefaultLookUp["generation"] = GENERATION
            DefaultLookUp["description"] = DESCRIPTION
            DefaultLookUp["role"] = ROLE
            DefaultLookUp["unstructuredaddress"] =
                UnstructuredAddress
            DefaultLookUp["unstructuredname"] = UnstructuredName
            DefaultLookUp["uniqueidentifier"] =
                UNIQUE_IDENTIFIER
            DefaultLookUp["dn"] = DN_QUALIFIER
            DefaultLookUp["pseudonym"] = PSEUDONYM
            DefaultLookUp["postaladdress"] = POSTAL_ADDRESS
            DefaultLookUp["nameatbirth"] = NAME_AT_BIRTH
            DefaultLookUp["countryofcitizenship"] =
                COUNTRY_OF_CITIZENSHIP
            DefaultLookUp["countryofresidence"] =
                COUNTRY_OF_RESIDENCE
            DefaultLookUp["gender"] = GENDER
            DefaultLookUp["placeofbirth"] = PLACE_OF_BIRTH
            DefaultLookUp["dateofbirth"] = DATE_OF_BIRTH
            DefaultLookUp["postalcode"] = POSTAL_CODE
            DefaultLookUp["businesscategory"] =
                BUSINESS_CATEGORY
            DefaultLookUp["telephonenumber"] = TELEPHONE_NUMBER
            DefaultLookUp["name"] = NAME
            DefaultLookUp["organizationidentifier"] =
                ORGANIZATION_IDENTIFIER
        }


        val instance: BCStyle
            get() {
                if (INSTANCE == null) {
                    synchronized(BCStyle::class.java) {
                        INSTANCE = BCStyle()
                    }
                }
                return INSTANCE!!
            }
    }
}
