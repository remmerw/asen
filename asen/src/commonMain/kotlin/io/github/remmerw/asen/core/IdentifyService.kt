package io.github.remmerw.asen.core

import io.github.remmerw.asen.TIMEOUT
import io.github.remmerw.asen.identifyPeerId
import io.github.remmerw.asen.quic.Connection
import io.github.remmerw.borr.PeerId
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.protobuf.ProtoBuf


internal fun identify(
    self: PeerId,
    agent: String,
    protocols: Set<String>
): Identify {
    return Identify(
        identifyPeerId(self), emptyList(), protocols.toList(), null, PROTOCOL_VERSION, agent
    )
}


@OptIn(ExperimentalSerializationApi::class)
internal fun identify(connection: Connection): Identify {
    val data = createStream(connection)
        .request(
            TIMEOUT.toLong(), encode(
                MULTISTREAM_PROTOCOL,
                IDENTITY_PROTOCOL
            )
        )
    val response = receiveResponse(data)

    return ProtoBuf.decodeFromByteArray<Identify>(response)
}


private const val PROTOCOL_VERSION: String = "ipfs/0.1.0"

