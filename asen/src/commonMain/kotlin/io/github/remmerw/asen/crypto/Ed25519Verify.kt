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
 * Ed25519 verifying.
 *
 *
 * The first call to this function may take longer, because Ed25519Constants needs to be
 * initialized.
 *
 *
 * <pre>`// get the publicKey from the other party.
 * Ed25519Verify verifier = new Ed25519Verify(publicKey);
 * try {
 * verifier.verify(signature, message);
 * } catch (Exception e) {
 * // all the rest of security exceptions.
 * }
`</pre> *
 */
internal class Ed25519Verify(publicKey: ByteArray) {
    private val publicKey: Bytes

    private val outputPrefix: ByteArray

    private val messageSuffix: ByteArray


    init {
        require(publicKey.size == PUBLIC_KEY_LEN) {
            "Given public key's length is not $PUBLIC_KEY_LEN"
        }
        this.publicKey = copyFrom(publicKey)
        this.outputPrefix = byteArrayOf()
        this.messageSuffix = byteArrayOf()
        Ed25519.init()
    }


    private fun noPrefixVerify(signature: ByteArray, data: ByteArray) {
        if (signature.size != SIGNATURE_LEN) {
            throw Exception(
                "The length of the signature is not $SIGNATURE_LEN"
            )
        }
        if (!Ed25519.verify(data, signature, publicKey.toByteArray())) {
            throw Exception("Signature check failed.")
        }
    }


    fun verify(signature: ByteArray, data: ByteArray) {
        if (outputPrefix.isEmpty() && messageSuffix.isEmpty()) {
            noPrefixVerify(signature, data)
            return
        }

        var dataCopy = data
        if (messageSuffix.isNotEmpty()) {
            dataCopy = concat(data, messageSuffix)
        }
        val signatureNoPrefix = signature.copyOfRange(outputPrefix.size, signature.size)
        noPrefixVerify(signatureNoPrefix, dataCopy)
    }

}
