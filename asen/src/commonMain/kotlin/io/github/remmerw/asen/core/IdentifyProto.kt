package io.github.remmerw.asen.core

import kotlinx.serialization.Serializable

/* proto definition
syntax = "proto2";
message Identify {
    optional string protocolVersion = 5;
    optional string agentVersion = 6;
    optional bytes publicKey = 1;
    repeated bytes listenAddrs = 2;
    optional bytes observedAddr = 4;
    repeated string protocols = 3;
}
*/
@Suppress("ArrayInDataClass")
@Serializable
data class Identify(
    val publicKey: ByteArray? = null,
    val listenAddrs: List<ByteArray> = emptyList(),
    val protocols: List<String> = emptyList(),
    val observedAddress: ByteArray? = null,
    val protocolVersion: String? = null,
    val agentVersion: String? = null,
)