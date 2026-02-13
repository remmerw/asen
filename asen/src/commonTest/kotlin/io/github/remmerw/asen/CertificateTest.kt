package io.github.remmerw.asen

import io.github.remmerw.asen.core.generateCertificate
import io.github.remmerw.borr.generateKeys
import kotlin.test.Test

class CertificateTest {

    @Test
    fun createCertificate() {
        val keys = generateKeys()
        val cert = generateCertificate(keys)
        checkNotNull(cert.x509)
        val encoded = cert.x509.encoded()
        checkNotNull(encoded.toString())
    }
}