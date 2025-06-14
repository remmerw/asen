package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.math.pow


/**
 * [
 * Quic transport parameter TLS extension.](https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e)
 */

internal data class TransportParametersExtension(
    val version: Int, val transportParameters: TransportParameters,
    val isClient: Boolean
) : Extension {
    override fun getBytes(): ByteArray {
        val buffer = Buffer()

        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.2
        // "quic_transport_parameters(0xffa5)"
        buffer.writeShort(CODEPOINT_V1.toShort())

        // Format is same as any TLS extension, so next are 2 bytes length
        buffer.writeShort(0.toShort()) // PlaceHolder, will be correctly set at the end of this method.

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2
        // "Those transport parameters that are identified as integers use a variable-length integer encoding (...) and
        //  have a default value of 0 if the transport parameter is absent, unless otherwise stated."
        if (!isClient) {
            // "The value of the Destination Connection ID field from the first Initial packet sent by the client (...)
            // This transport parameter is only sent by a server."

            addTransportParameter(
                buffer,
                TransportParameterId.ORIGINAL_DESTINATION_CID,
                transportParameters.originalDcid
            )
        }

        // "The max idle timeout is a value in milliseconds that is encoded as an integer"
        addTransportParameter(
            buffer,
            TransportParameterId.MAX_IDLE_TIMEOUT,
            transportParameters.maxIdleTimeout.toLong()
        )

        if (!isClient && transportParameters.statelessResetToken != null) {
            // "A stateless reset token is used in verifying a stateless reset (...). This parameter is a sequence of 16
            //  bytes. This transport parameter MUST NOT be sent by a client, but MAY be sent by a server."
            addTransportParameter(
                buffer,
                TransportParameterId.STATELESS_RESET_TOKEN,
                transportParameters.statelessResetToken
            )
        }

        // "The maximum UDP payload size parameter is an integer value that limits the size of UDP payloads that the
        //  endpoint is willing to receive.  UDP datagrams with payloads larger than this limit are not likely to be
        //  processed by the receiver."
        addTransportParameter(
            buffer,
            TransportParameterId.MAX_UDP_PAYLOAD_SIZE,
            transportParameters.maxUdpPayloadSize.toLong()
        )

        // "The initial maximum data parameter is an integer value that contains the initial value for the maximum
        //  amount of data that can be sent on the connection.  This is equivalent to sending a MAX_DATA for the
        //  connection immediately after completing the handshake."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_DATA,
            transportParameters.initialMaxData.toLong()
        )

        // "This parameter is an integer value specifying the initial flow control limit for locally-initiated
        //  bidirectional streams. This limit applies to newly created bidirectional streams opened by the endpoint that
        //  sends the transport parameter."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            transportParameters.initialMaxStreamDataBidiLocal.toLong()
        )

        // "This parameter is an integer value specifying the initial flow control limit for peer-initiated bidirectional
        //  streams. This limit applies to newly created bidirectional streams opened by the endpoint that receives
        //  the transport parameter."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            transportParameters.initialMaxStreamDataBidiRemote.toLong()
        )

        // "This parameter is an integer value specifying the initial flow control limit for unidirectional streams.
        //  This limit applies to newly created bidirectional streams opened by the endpoint that receives the transport
        //  parameter."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_STREAM_DATA_UNI,
            transportParameters.initialMaxStreamDataUni.toLong()
        )

        // "The initial maximum bidirectional streams parameter is an integer value that contains the initial maximum
        //  number of bidirectional streams the peer may initiate.  If this parameter is absent or zero, the peer cannot
        //  open bidirectional streams until a MAX_STREAMS frame is sent."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_STREAMS_BIDI,
            transportParameters.initialMaxStreamsBidi.toLong()
        )

        // "The initial maximum unidirectional streams parameter is an integer value that contains the initial maximum
        //  number of unidirectional streams the peer may initiate. If this parameter is absent or zero, the peer cannot
        //  open unidirectional streams until a MAX_STREAMS frame is sent."
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_MAX_STREAMS_UNI,
            transportParameters.initialMaxStreamsUni.toLong()
        )

        // "The acknowledgement delay exponent is an integer value indicating an exponent used to decode the ACK Delay
        // field in the ACK frame"
        addTransportParameter(
            buffer,
            TransportParameterId.ACK_DELAY_EXPONENT,
            transportParameters.ackDelayExponent.toLong()
        )

        // "The maximum acknowledgement delay is an integer value indicating the maximum amount of time in milliseconds
        //  by which the endpoint will delay sending acknowledgments."
        addTransportParameter(
            buffer,
            TransportParameterId.MAX_ACK_DELAY,
            transportParameters.maxAckDelay.toLong()
        )

        // The max_datagram_frame_size transport parameter is an integer value
        // (represented as a variable-length integer) that represents the maximum size of a
        // DATAGRAM frame (including the frame payloadType, length, and payload) the endpoint is willing
        // to receive, in bytes. An endpoint that includes this parameter supports the DATAGRAM
        // frame types and is willing to receive such frames on this connection.
        addTransportParameter(
            buffer,
            TransportParameterId.MAX_DATAGRAM_FRAME_SIZE,
            transportParameters.maxDatagramFrameSize.toLong()
        )

        // Intentionally omitted (kwik server supports active migration)
        // disable_active_migration

        // Intentionally omitted (kwik server does not support preferred address)
        // preferred_address

        // "The maximum number of connection IDs from the peer that an endpoint is willing to store."
        addTransportParameter(
            buffer,
            TransportParameterId.ACTIVE_CONNECTION_ID_LIMIT,
            transportParameters.activeConnectionIdLimit.toLong()
        )

        // "The value that the endpoint included in the Source Connection ID field of the first Initial packet it
        //  sends for the connection"
        addTransportParameter(
            buffer,
            TransportParameterId.INITIAL_SOURCE_CID,
            transportParameters.initialScid
        )

        if (!isClient) {
            // "The value that the the server included in the Source Connection ID field of a Retry packet"
            // "This transport parameter is only sent by a server."
            if (transportParameters.retrySourceConnectionId != null) {
                addTransportParameter(
                    buffer,
                    TransportParameterId.RETRY_SOURCE_CID,
                    transportParameters.retrySourceConnectionId
                )
            }
        }


        if (transportParameters.versionInformation != null) {
            val versions = transportParameters.versionInformation
            val length = 4 + versions.otherVersions.size * 4
            val data = Buffer()
            data.write(Version.toBytes(versions.chosenVersion))
            for (version in versions.otherVersions) {
                data.write(Version.toBytes(version))
            }
            require(data.size.toInt() == length)
            addTransportParameter(
                buffer,
                TransportParameterId.VERSION_INFORMATION,
                data.readByteArray()
            )
        }

        val data = buffer.readByteArray()


        val extensionsSize =
            data.size - 2 - 2 // 2 bytes for the length itself and 2 for the payloadType

        data[3] = (extensionsSize and 0xff).toByte()
        data[2] = ((extensionsSize shr 8) and 0xff).toByte()

        return data
    }

    override fun extension(): ExtensionClass {
        return ExtensionClass.TRANSPORT_PARAMETERS
    }


    companion object {
        private const val CODEPOINT_V1 = 0x39

        /**
         * Creates a Quic Transport Parameters Extension for use in a Client Hello.
         */
        fun create(
            version: Int, params: TransportParameters, isClient: Boolean
        ): TransportParametersExtension {
            return TransportParametersExtension(version, params, isClient)
        }

        fun isCodepoint(extensionType: Int): Boolean {
            return extensionType == CODEPOINT_V1
        }

        private fun allZero(data: ByteArray): Boolean {
            for (datum in data) {
                if (datum.toInt() != 0) {
                    return false
                }
            }
            return true
        }


        fun parse(
            version: Int, buffer: Buffer, extensionLength: Int, isClient: Boolean
        ): TransportParametersExtension {

            val bytes = buffer.readByteArray(extensionLength)
            val transport = Buffer()
            transport.write(bytes)

            val transportParameters = parseTransportParameter(transport)

            return TransportParametersExtension(version, transportParameters, isClient)
        }


        private fun parseTransportParameter(buffer: Buffer): TransportParameters {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2
            // "The default for this parameter is the maximum permitted UDP payload of 65527"

            var maxUdpPayloadSize = Settings.DEFAULT_MAX_UDP_PAYLOAD_SIZE
            // "If this value is absent, a default value of 3 is assumed (indicating a multiplier of 8)."
            var ackDelayExponent = Settings.DEFAULT_ACK_DELAY_EXPONENT
            // "If this value is absent, a default of 25 milliseconds is assumed."
            var maxAckDelay = Settings.DEFAULT_MAX_ACK_DELAY
            // "If this transport parameter is absent, a default of 2 is assumed."
            var activeConnectionIdLimit = Settings.DEFAULT_ACTIVE_CONNECTION_ID_LIMIT

            var preferredAddress: TransportParameters.PreferredAddress? = null
            var versionInformation: TransportParameters.VersionInformation? = null
            var originalDcid: Number? = null
            var maxIdleTimeout = 0
            var initialMaxData = 0
            var initialMaxStreamDataBidiLocal = 0
            var initialMaxStreamDataBidiRemote = 0
            var initialMaxStreamDataUni = 0
            var initialMaxStreamsBidi = 0
            var initialMaxStreamsUni = 0
            var maxDatagramFrameSize = 0
            var initialScid: Number? = null
            var retrySourceConnectionId: ByteArray? = null
            var statelessResetToken: ByteArray? = null
            var disableMigration = false


            while (!buffer.exhausted()) {
                val parameterId: Long = parseLong(buffer)
                val size: Int = parseInt(buffer)
                if (buffer.size < size) {
                    error("Invalid transport parameter extension")
                }

                if (parameterId == TransportParameterId.ORIGINAL_DESTINATION_CID.value.toLong()) {
                    originalDcid = if (size == Int.SIZE_BYTES) {
                        buffer.readInt()
                    } else {
                        if (size == Long.SIZE_BYTES) {
                            buffer.readLong()
                        } else {
                            error("Invalid transport parameter extension")
                        }
                    }
                } else if (parameterId == TransportParameterId.MAX_IDLE_TIMEOUT.value.toLong()) {
                    maxIdleTimeout = parseInt(buffer)
                } else if (parameterId == TransportParameterId.STATELESS_RESET_TOKEN.value.toLong()) {
                    statelessResetToken = buffer.readByteArray(16)
                } else if (parameterId == TransportParameterId.MAX_UDP_PAYLOAD_SIZE.value.toLong()) {
                    maxUdpPayloadSize = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_DATA.value.toLong()) {
                    initialMaxData = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL.value.toLong()) {
                    initialMaxStreamDataBidiLocal = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE.value.toLong()) {
                    initialMaxStreamDataBidiRemote = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_STREAM_DATA_UNI.value.toLong()) {
                    initialMaxStreamDataUni = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_STREAMS_BIDI.value.toLong()) {
                    initialMaxStreamsBidi = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_MAX_STREAMS_UNI.value.toLong()) {
                    initialMaxStreamsUni = parseInt(buffer)
                } else if (parameterId == TransportParameterId.ACK_DELAY_EXPONENT.value.toLong()) {
                    ackDelayExponent = parseInt(buffer)
                } else if (parameterId == TransportParameterId.MAX_ACK_DELAY.value.toLong()) {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-30#section-18.2
                    // "The maximum acknowledgement delay is an integer value indicating the maximum amount of time in
                    //  milliseconds by which the endpoint will delay sending acknowledgments. "
                    maxAckDelay = parseInt(buffer)
                } else if (parameterId == TransportParameterId.DISABLE_ACTIVE_MIGRATION.value.toLong()) {
                    disableMigration = true
                } else if (parameterId == TransportParameterId.PREFERRED_ADDRESS.value.toLong()) {
                    preferredAddress = parsePreferredAddress(buffer)
                } else if (parameterId == TransportParameterId.ACTIVE_CONNECTION_ID_LIMIT.value.toLong()) {
                    activeConnectionIdLimit =
                        parseLong(buffer).toInt()
                } else if (parameterId == TransportParameterId.MAX_DATAGRAM_FRAME_SIZE.value.toLong()) {
                    maxDatagramFrameSize = parseInt(buffer)
                } else if (parameterId == TransportParameterId.INITIAL_SOURCE_CID.value.toLong()) {
                    if (size == Int.SIZE_BYTES) {
                        initialScid = buffer.readInt()
                    } else {
                        error("Invalid transport parameter extension")
                    }
                } else if (parameterId == TransportParameterId.RETRY_SOURCE_CID.value.toLong()) {
                    retrySourceConnectionId = buffer.readByteArray(size)
                } else if (parameterId == TransportParameterId.VERSION_INFORMATION.value.toLong()) {
                    // https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-05.html#name-version-information
                    if (size % 4 != 0 || size < 4) {
                        error("invalid parameters size")
                    }
                    val chosenVersion = buffer.readInt()
                    val otherVersions: MutableList<Int> = arrayListOf()
                    repeat(size / 4 - 1) {
                        val otherVersion = buffer.readInt()
                        otherVersions.add(otherVersion)
                    }

                    val versions = IntArray(otherVersions.size)
                    for (i in otherVersions.indices) {
                        versions[i] = otherVersions[i]
                    }

                    versionInformation = TransportParameters.VersionInformation(
                        chosenVersion, versions
                    )
                } else {
                    // Reserved Transport Parameters
                    //
                    //   Transport parameters with an identifier of the form "31 * N + 27" for
                    //   integer values of N are reserved to exercise the requirement that
                    //   unknown transport parameters be ignored.  These transport parameters
                    //   have no semantics, and can carry and can carry arbitrary values.

                    // https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-34#section-18.1
                    buffer.skip(size.toLong())
                }


            }
            return TransportParameters(
                preferredAddress, versionInformation, originalDcid,
                maxIdleTimeout, initialMaxData, initialMaxStreamDataBidiLocal,
                initialMaxStreamDataBidiRemote, initialMaxStreamDataUni, initialMaxStreamsBidi,
                initialMaxStreamsUni, ackDelayExponent, maxAckDelay, activeConnectionIdLimit,
                maxUdpPayloadSize, initialScid, retrySourceConnectionId,
                statelessResetToken, disableMigration, maxDatagramFrameSize,
                2.0f.pow(ackDelayExponent.toFloat()).toInt()
            )
        }


        private fun parsePreferredAddress(buffer: Buffer): TransportParameters.PreferredAddress {

            val ip4 = buffer.readByteArray(4)

            var inet4: ByteArray? = null
            if (!allZero(ip4)) {
                inet4 = ip4
            }
            val portIp4 = ((buffer.readByte().toInt() shl 8) or buffer.readByte().toInt())
            val ip6 = buffer.readByteArray(16)

            var inet6: ByteArray? = null
            if (!allZero(ip6)) {
                inet6 = ip6
            }
            val portIp6 = ((buffer.readByte().toInt() shl 8) or buffer.readByte().toInt())

            if (inet4 == null && inet6 == null) {
                error("Invalid preferred address")
            }

            val connectionIdSize = buffer.readByte().toInt()

            val connectionId = buffer.readByteArray(connectionIdSize)

            val statelessResetToken = buffer.readByteArray(16)

            return TransportParameters.PreferredAddress(
                inet4, portIp4,
                inet6, portIp6, connectionId, statelessResetToken
            )

        }

        private fun addTransportParameter(
            buffer: Buffer,
            id: TransportParameterId,
            value: Long
        ) {
            addTransportParameter(buffer, id.value, value)
        }

        private fun addTransportParameter(buffer: Buffer, id: Int, value: Long) {
            encode(id, buffer)
            val encodedValueLength: Int = bytesNeeded(value)
            encode(encodedValueLength, buffer)
            encode(value, buffer)
        }

        private fun addTransportParameter(
            buffer: Buffer,
            id: TransportParameterId,
            value: ByteArray
        ) {
            addTransportParameter(buffer, id.value, value)
        }

        private fun addTransportParameter(
            buffer: Buffer,
            id: TransportParameterId,
            dcid: Number?
        ) {
            addTransportParameter(buffer, id.value, dcid)
        }

        private fun addTransportParameter(buffer: Buffer, id: Int, value: ByteArray) {
            encode(id, buffer)
            encode(value.size, buffer)
            buffer.write(value)
        }

        private fun addTransportParameter(buffer: Buffer, id: Int, number: Number?) {
            encode(id, buffer)

            when (number) {
                is Long -> {
                    encode(Long.SIZE_BYTES, buffer)
                    buffer.writeLong(number)
                }

                is Int -> {
                    encode(Int.SIZE_BYTES, buffer)
                    buffer.writeInt(number)
                }

                else -> {
                    throw IllegalStateException("not supported")
                }
            }
        }
    }
}
