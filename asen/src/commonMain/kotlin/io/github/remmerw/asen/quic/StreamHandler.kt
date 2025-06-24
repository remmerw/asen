package io.github.remmerw.asen.quic

import kotlinx.io.Buffer

interface StreamHandler {
    fun terminated()

    fun fin()

    fun readFully(): Boolean

    suspend fun data(data: Buffer)
}
