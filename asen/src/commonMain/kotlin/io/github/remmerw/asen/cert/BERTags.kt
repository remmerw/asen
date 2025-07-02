package io.github.remmerw.asen.cert

internal interface BERTags {
    companion object {
        const val BOOLEAN: Int = 0x01
        const val INTEGER: Int = 0x02
        const val BIT_STRING: Int = 0x03
        const val OCTET_STRING: Int = 0x04
        const val NULL: Int = 0x05
        const val OBJECT_IDENTIFIER: Int = 0x06
        const val OBJECT_DESCRIPTOR: Int = 0x07
        const val ENUMERATED: Int = 0x0a // decimal 10
        const val UTF8_STRING: Int = 0x0c // decimal 12
        const val RELATIVE_OID: Int = 0x0d // decimal 13

        // NOTE: 14-15 are reserved.
        const val SEQUENCE: Int = 0x10 // decimal 16
        const val SET: Int = 0x11 // decimal 17
        const val NUMERIC_STRING: Int = 0x12 // decimal 18
        const val PRINTABLE_STRING: Int = 0x13 // decimal 19
        const val T61_STRING: Int = 0x14 // decimal 20
        const val VIDEOTEX_STRING: Int = 0x15 // decimal 21
        const val IA5_STRING: Int = 0x16 // decimal 22
        const val UTC_TIME: Int = 0x17 // decimal 23
        const val GENERALIZED_TIME: Int = 0x18 // decimal 24
        const val GRAPHIC_STRING: Int = 0x19 // decimal 25
        const val VISIBLE_STRING: Int = 0x1a // decimal 26
        const val GENERAL_STRING: Int = 0x1b // decimal 27
        const val UNIVERSAL_STRING: Int = 0x1c // decimal 28
        const val BMP_STRING: Int = 0x1e // decimal 30

        const val CONSTRUCTED: Int = 0x20 // decimal 32

        const val UNIVERSAL: Int = 0x00 // decimal 32

        const val CONTEXT_SPECIFIC: Int = 0x80 // decimal 128

        const val FLAGS: Int = 0xE0
    }
}
