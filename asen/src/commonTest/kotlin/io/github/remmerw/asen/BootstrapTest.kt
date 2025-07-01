package io.github.remmerw.asen

import io.github.remmerw.asen.core.resolveAddresses
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNotNull

class BootstrapTest {

    @Test
    fun bootstrap(): Unit = runBlocking(Dispatchers.IO) {

        val addresses = resolveAddresses()
        assertNotNull(addresses)
    }
}