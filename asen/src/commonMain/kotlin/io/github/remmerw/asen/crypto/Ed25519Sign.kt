// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package io.github.remmerw.asen.crypto


/**
 * Ed25519 signing.
 *
 *
 * <pre>`Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
 * // securely store keyPair and share keyPair.getPublicKey()
 * Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
 * byte[] signature = signer.sign(message);
`</pre> *
 *
 * @since 1.1.0
 */
internal class Ed25519Sign(privateKey: ByteArray) {
    private val hashedPrivateKey: ByteArray
    private val publicKey: ByteArray
    private val outputPrefix: ByteArray
    private val messageSuffix: ByteArray


    init {
        require(privateKey.size == SECRET_KEY_LEN) {
            "Given private key's length is not $SECRET_KEY_LEN"
        }

        this.hashedPrivateKey = Ed25519.getHashedScalar(privateKey)
        this.publicKey = Ed25519.scalarMultWithBaseToBytes(this.hashedPrivateKey)
        this.outputPrefix = byteArrayOf()
        this.messageSuffix = byteArrayOf()
    }

    private fun noPrefixSign(data: ByteArray): ByteArray {
        return Ed25519.sign(data, publicKey, hashedPrivateKey)
    }

    fun sign(data: ByteArray): ByteArray {
        val signature = if (messageSuffix.isEmpty()) {
            noPrefixSign(data)
        } else {
            noPrefixSign(concat(data, messageSuffix))
        }
        return if (outputPrefix.isEmpty()) {
            signature
        } else {
            concat(outputPrefix, signature)
        }
    }

    /**
     * Defines the KeyPair consisting of a private key and its corresponding public key.
     */
    class KeyPair private constructor(
        private val publicKey: ByteArray,
        private val privateKey: ByteArray
    ) {
        fun getPublicKey(): ByteArray {
            return publicKey.copyOf(publicKey.size)
        }

        fun getPrivateKey(): ByteArray {
            return privateKey.copyOf(privateKey.size)
        }

        companion object {

            fun newKeyPair(): KeyPair {
                return newKeyPairFromSeed(randBytes(Field25519.FIELD_LEN))
            }


            fun newKeyPairFromSeed(secretSeed: ByteArray): KeyPair {
                require(secretSeed.size == Field25519.FIELD_LEN) {
                    "Given secret seed length is not " + Field25519.FIELD_LEN
                }
                val publicKey =
                    Ed25519.scalarMultWithBaseToBytes(Ed25519.getHashedScalar(secretSeed))
                return KeyPair(publicKey, secretSeed)
            }
        }
    }

}
