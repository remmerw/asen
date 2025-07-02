package io.github.remmerw.asen.cert


internal class OIDTokenizer(private val oid: String) {
    private var index = 0

    /**
     * Return whether or not there are more tokens in this tokenizer.
     *
     * @return true if there are more tokens, false otherwise.
     */
    fun hasMoreTokens(): Boolean {
        return (index != -1)
    }

    /**
     * Return the next token in the underlying String.
     *
     * @return the next token.
     */
    fun nextToken(): String? {
        if (index == -1) {
            return null
        }

        val token: String
        val end = oid.indexOf('.', index)

        if (end == -1) {
            token = oid.substring(index)
            index = -1
            return token
        }

        token = oid.substring(index, end)

        index = end + 1
        return token
    }
}
