package io.github.remmerw.asen.cert

internal class X500NameTokenizer(
    private val value: String,
    private val separator: Char = ','
) {
    private var index: Int

    init {
        this.index = -1
    }

    fun hasMoreTokens(): Boolean {
        return (index != value.length)
    }

    fun nextToken(): String? {
        if (index == value.length) {
            return null
        }

        var end = index + 1
        var quoted = false
        var escaped = false
        val buf = StringBuilder()
        buf.setLength(0)

        while (end != value.length) {
            val c = value[end]

            if (c == '"') {
                if (!escaped) {
                    quoted = !quoted
                }
                buf.append(c)
                escaped = false
            } else {
                if (escaped || quoted) {
                    buf.append(c)
                    escaped = false
                } else if (c == '\\') {
                    buf.append(c)
                    escaped = true
                } else if (c == separator) {
                    break
                } else {
                    buf.append(c)
                }
            }
            end++
        }

        index = end

        return buf.toString()
    }
}
