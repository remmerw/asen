package io.github.remmerw.asen.quic

import org.kotlincrypto.macs.hmac.sha2.HmacSHA256
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

open class ConnectionSecrets(internal val version: Int) {
    @OptIn(ExperimentalAtomicApi::class)
    private val clientSecretsInitial = AtomicReference<Keys?>(null)

    @OptIn(ExperimentalAtomicApi::class)
    private val serverSecretsInitial = AtomicReference<Keys?>(null)

    @OptIn(ExperimentalAtomicApi::class)
    private val clientSecretsHandshake = AtomicReference<Keys?>(null)

    @OptIn(ExperimentalAtomicApi::class)
    private val serverSecretsHandshake = AtomicReference<Keys?>(null)

    @OptIn(ExperimentalAtomicApi::class)
    private val clientSecretsApp = AtomicReference<Keys?>(null)

    @OptIn(ExperimentalAtomicApi::class)
    private val serverSecretsApp = AtomicReference<Keys?>(null)


    /**
     * Generate the initial secrets
     */
    @OptIn(ExperimentalAtomicApi::class)
    internal fun computeInitialKeys(dcid: Number) {
        val initialSecret = computeInitialSecret(version, dcid)

        clientSecretsInitial.store(Keys.createInitialKeys(version, initialSecret, true))
        serverSecretsInitial.store(Keys.createInitialKeys(version, initialSecret, false))
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun createKeys(
        level: Level,
        secrets: TrafficSecrets,
        selectedCipherSuite: CipherSuite
    ) {
        check(selectedCipherSuite == CipherSuite.TLS_AES_128_GCM_SHA256) { "unsupported cipher suite $selectedCipherSuite" }

        when (level) {
            Level.Handshake -> {
                clientSecretsHandshake.store(
                    Keys.computeHandshakeKeys(version, true, secrets)
                )

                serverSecretsHandshake.store(
                    Keys.computeHandshakeKeys(version, false, secrets)
                )

            }

            Level.App -> {
                clientSecretsApp.store(
                    Keys.computeApplicationKeys(version, true, secrets)
                )

                serverSecretsApp.store(
                    Keys.computeApplicationKeys(version, false, secrets)
                )

            }

            else -> throw RuntimeException("not supported level")
        }
    }

    internal fun computeHandshakeSecrets(
        secrets: TrafficSecrets,
        selectedCipherSuite: CipherSuite
    ) {
        createKeys(Level.Handshake, secrets, selectedCipherSuite)
    }

    internal fun computeApplicationSecrets(
        secrets: TrafficSecrets,
        selectedCipherSuite: CipherSuite
    ) {
        createKeys(Level.App, secrets, selectedCipherSuite)
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun remoteSecrets(level: Level): Keys? {
        return when (level) {
            Level.Initial -> serverSecretsInitial.load()
            Level.App -> serverSecretsApp.load()
            Level.Handshake -> serverSecretsHandshake.load()
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun remoteSecrets(level: Level, keys: Keys) {
        when (level) {
            Level.Initial -> serverSecretsInitial.store(keys)
            Level.App -> serverSecretsApp.store(keys)
            Level.Handshake -> serverSecretsHandshake.store(keys)
        }
    }


    @OptIn(ExperimentalAtomicApi::class)
    internal fun ownSecrets(level: Level, keys: Keys) {
        when (level) {
            Level.Initial -> clientSecretsInitial.store(keys)
            Level.App -> clientSecretsApp.store(keys)
            Level.Handshake -> clientSecretsHandshake.store(keys)
        }
    }


    @OptIn(ExperimentalAtomicApi::class)
    internal fun ownSecrets(level: Level): Keys? {
        return when (level) {
            Level.Initial -> clientSecretsInitial.load()
            Level.App -> clientSecretsApp.load()
            Level.Handshake -> clientSecretsHandshake.load()
        }
    }


    @OptIn(ExperimentalAtomicApi::class)
    internal fun discardHandshakeKeys() {
        clientSecretsHandshake.store(null)
        serverSecretsHandshake.store(null)
    }


    @OptIn(ExperimentalAtomicApi::class)
    internal fun discardInitialKeys() {
        clientSecretsInitial.store(null)
        serverSecretsInitial.store(null)
    }

    @OptIn(ExperimentalAtomicApi::class)
    internal fun discardKeys() {
        clientSecretsHandshake.store(null)
        serverSecretsHandshake.store(null)
        clientSecretsInitial.store(null)
        serverSecretsInitial.store(null)
        clientSecretsApp.store(null)
        serverSecretsApp.store(null)
    }


    private fun hmacSHA256(initialSalt: ByteArray, inputKeyingMaterial: ByteArray): ByteArray {
        val mac = HmacSHA256(initialSalt)
        require(inputKeyingMaterial.isNotEmpty()) {
            "provided inputKeyingMaterial must be at least of size 1 and not null"
        }
        return mac.doFinal(inputKeyingMaterial)
    }

    private fun computeInitialSecret(actualVersion: Int, dcid: Number): ByteArray {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"

        val initialSalt = if (Version.isV2(actualVersion))
            Settings.STATIC_SALT_V2 else Settings.STATIC_SALT_V1

        return hmacSHA256(initialSalt, numToBytes(dcid))
    }

}
