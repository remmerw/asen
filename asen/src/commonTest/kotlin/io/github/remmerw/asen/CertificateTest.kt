package io.github.remmerw.asen

import io.github.remmerw.asen.core.createCertificateNott
import kotlin.test.Test

class CertificateTest {

    @Test
    fun createCertificate(){
        val keys = generateKeys()
        val cert = createCertificateNott(keys)
        checkNotNull(cert)
    }
}