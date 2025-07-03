package io.github.remmerw.asen

import io.github.remmerw.asen.core.generateCertificate
import kotlin.test.Test

class CertificateTest {

    @Test
    fun createCertificate(){
        val keys = generateKeys()
        val cert = generateCertificate(keys)
        checkNotNull(cert)
        val encoded = cert.encoded()
        checkNotNull(encoded)
    }
}