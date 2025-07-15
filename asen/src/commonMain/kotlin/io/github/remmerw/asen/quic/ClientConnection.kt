package io.github.remmerw.asen.quic

import io.github.remmerw.asen.PeerId
import io.github.remmerw.asen.debug
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.isClosed
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi


class ClientConnection internal constructor(
    version: Int,
    private val selectorManager: SelectorManager,
    remotePeerId: PeerId,
    remoteAddress: InetSocketAddress,
    cipherSuites: List<CipherSuite>,
    certificate: Certificate,
    responder: Responder,
    private val connector: Connector
) : Connection(version, remotePeerId, remoteAddress, responder) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private val tlsEngine: TlsClientEngine
    private val handshakeDone = Semaphore(1, 1)
    private val transportParams: TransportParameters

    private val scidRegistry = ScidRegistry()
    private val dcidRegistry: DcidRegistry
    private val originalDcid: Number

    /**
     * The maximum numbers of connection IDs this endpoint can use; determined by the TP
     * supplied by the peer
     */
    @OptIn(ExperimentalAtomicApi::class)
    private val remoteCidLimit = AtomicInt(Settings.ACTIVE_CONNECTION_ID_LIMIT)

    init {
        val initialScid = scidRegistry.initial as Int

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
        // "When an Initial packet is sent by a client (...), the client populates the Destination
        // Connection ID field with an unpredictable value.
        // This Destination Connection ID MUST be at least 8 bytes in length."
        this.originalDcid = generateNumber(Long.SIZE_BYTES)

        this.dcidRegistry = DcidRegistry(originalDcid)


        var versionInformation: TransportParameters.VersionInformation? = null
        if (Version.isV2(version)) {
            val otherVersions = intArrayOf(Version.V2, Version.V1)
            versionInformation = TransportParameters.VersionInformation(
                Version.V2, otherVersions
            )
        }

        this.transportParams = TransportParameters.createClient(
            initialScid,
            Settings.ACTIVE_CONNECTION_ID_LIMIT, versionInformation
        )

        val tpExtension: Extension = TransportParametersExtension.create(
            this.version, transportParams, true
        )
        val aplnExtension: Extension = ApplicationLayerProtocolNegotiationExtension.create(
            Settings.ALPN
        )



        this.tlsEngine = TlsClientEngine(
            remoteAddress.hostname, certificate, cipherSuites,
            listOf(tpExtension, aplnExtension), CryptoMessageSender(), StatusEventHandler()
        )
        initializeCryptoStreams(tlsEngine)
    }


    suspend fun connect(timeout: Int) {

        try {
            startHandshake()
        } catch (throwable: Throwable) {
            abortHandshake()
            throw Exception("Error : " + throwable.message)
        }

        try {
            withTimeout(timeout * 1000L) {
                handshakeDone.acquire()
                if (state() != State.Connected) {
                    abortHandshake()
                    throw Exception("Handshake error state is " + state())
                }
                connector.addConnection(this@ClientConnection)
            }
        } catch (throwable: Throwable) {
            abortHandshake()
            throw throwable
        }
    }

    override fun scheduleTerminate(pto: Int) {
        scope.launch {
            delay(pto.toLong())
            terminate()
        }
    }

    private suspend fun startHandshake() {
        computeInitialKeys(dcidRegistry.initial)

        socket = aSocket(selectorManager).udp().bind(
            InetSocketAddress("::", 0)
        )

        scope.launch {
            runReceiver()
        }
        scope.launch {
            runRequester()
        }

        tlsEngine.startHandshake()
    }


    private suspend fun abortHandshake() {
        state(State.Failed)
        clearRequests()
        terminate()
    }


    /**
     * Registers the initial connection ID issued by the peer (server). Used in client role only.
     */
    private fun registerInitialCid(cid: Int) {
        dcidRegistry.initialConnectionId(cid)
    }

    /**
     * Registers that the given connection is used by the peer (as destination connection ID)
     * to send messages to this endpoint.
     *
     * @param cid the connection ID used
     */
    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun registerCidInUse(cid: Number) {
        if (scidRegistry.registerUsedConnectionId(cid)) {
            // New connection id, not used before.
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
            // "If an endpoint provided fewer connection IDs than the peer's active_connection_id_limit, it MAY supply
            //  a new connection ID when it receives a packet with a previously unused connection ID."
            if (scidRegistry.activeCids < remoteCidLimit.load()) {
                sendNewCid()
            }
        }
    }


    override suspend fun process(packetHeader: PacketHeader): Boolean {
        when (packetHeader.level) {
            Level.Handshake -> {
                return processFrames(packetHeader)
            }

            Level.Initial -> {
                registerInitialCid(packetHeader.scid!!)
                return processFrames(packetHeader)
            }

            Level.App -> {
                registerCidInUse(packetHeader.dcid)
                return processFrames(packetHeader)
            }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    override suspend fun handshakeDone() {

        if (handshakeState.load().transitionAllowed(HandshakeState.Confirmed)) {
            handshakeState.store(HandshakeState.Confirmed)
        }
        val state = handshakeState.load()

        require(
            state == HandshakeState.Confirmed
        ) { "Handshake state cannot be set to Confirmed" }


        discard(Level.Handshake)

        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.2
        // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
        // 4.9.2. Discarding Handshake Keys
        // An endpoint MUST discard its handshake keys when the TLS handshake is confirmed
        // (Section 4.1.2).
        discardHandshakeKeys()
    }

    /**
     * Send a retire connection ID frame, that informs the peer the given connection ID will not be used by this
     * endpoint anymore for addressing the peer.
     */
    private suspend fun sendRetireCid(seqNr: Int) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "Likewise, retired connection IDs are sent in RETIRE_CONNECTION_ID frames and retransmitted if the packet
        //  containing them is lost."
        sendRequestQueue(Level.App).appendRequest(createRetireConnectionsIdFrame(seqNr))
    }

    override suspend fun process(newConnectionIdFrame: FrameReceived.NewConnectionIdFrame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
        // "Receiving a value in the Retire Prior To field that is greater than that in the
        // Sequence Number field MUST
        //  be treated as a connection error of payloadType FRAME_ENCODING_ERROR."

        if (newConnectionIdFrame.retirePriorTo > newConnectionIdFrame.sequenceNr) {
            immediateCloseWithError(
                Level.App,
                TransportError(TransportError.Code.FRAME_ENCODING_ERROR)
            )
            return
        }
        val cidInfo = dcidRegistry.cidInfo(newConnectionIdFrame.sequenceNr)
        if (cidInfo == null) {
            val added = dcidRegistry.registerNewConnectionId(
                newConnectionIdFrame.sequenceNr,
                newConnectionIdFrame.connectionId
            )
            if (!added) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
                // "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number
                // smaller than the Retire Prior To
                //  field of a previously received NEW_CONNECTION_ID frame MUST send a
                //  corresponding RETIRE_CONNECTION_ID
                //  frame that retires the newly received connection ID, "
                sendRetireCid(newConnectionIdFrame.sequenceNr)
            }
        } else if (cidInfo.cid() != newConnectionIdFrame.connectionId) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
            // "... or if a sequence number is used for different connection IDs, the endpoint
            // MAY treat that receipt as a
            //  connection error of payloadType PROTOCOL_VIOLATION."
            immediateCloseWithError(
                Level.App,
                TransportError(TransportError.Code.PROTOCOL_VIOLATION)
            )
            return
        }
        if (newConnectionIdFrame.retirePriorTo > 0) {
            val retired = dcidRegistry.retireAllBefore(newConnectionIdFrame.retirePriorTo)
            retired.forEach { seqNr: Int -> this.sendRetireCid(seqNr) }
        }
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "After processing a NEW_CONNECTION_ID frame and adding and retiring active connection
        // IDs, if the number of
        // active connection IDs exceeds the value advertised in its active_connection_id_limit
        // transport parameter, an
        // endpoint MUST close the connection with an error of payloadType CONNECTION_ID_LIMIT_ERROR."
        if (dcidRegistry.activeCids > Settings.ACTIVE_CONNECTION_ID_LIMIT) {
            immediateCloseWithError(
                Level.App,
                TransportError(TransportError.Code.CONNECTION_ID_LIMIT_ERROR)
            )
        }
    }


    @OptIn(ExperimentalAtomicApi::class)
    override suspend fun process(
        retireConnectionIdFrame: FrameReceived.RetireConnectionIdFrame,
        dcid: Number
    ) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
        // "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater
        // than any previously sent to the
        // peer MUST be treated as a connection error of payloadType PROTOCOL_VIOLATION."
        if (retireConnectionIdFrame.sequenceNumber > scidRegistry.maxSequenceNr()) {
            immediateCloseWithError(
                Level.App,
                TransportError(TransportError.Code.PROTOCOL_VIOLATION)
            )
            return
        }
        val sequenceNr = retireConnectionIdFrame.sequenceNumber
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
        // "The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the
        //  Destination Connection ID field of the packet in which the frame is contained.
        //  The peer MAY treat this as a connection error of payloadType PROTOCOL_VIOLATION."
        if (scidRegistry.cidInfo(sequenceNr)!!.cid() == dcid
        ) {
            immediateCloseWithError(
                Level.App,
                TransportError(TransportError.Code.PROTOCOL_VIOLATION)
            )
            return
        }

        val retiredCid: Number? = scidRegistry.retireCid(sequenceNr)
        // If not retired already
        if (retiredCid != null) {
            // connectionRegistry.deregisterConnectionId(retiredCid);
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
            // "An endpoint SHOULD supply a new connection ID when the peer retires a connection ID."
            if (scidRegistry.activeCids < remoteCidLimit.load()) {
                sendNewCid()
            }
        }
    }

    /**
     * Generate, register and send a new connection ID (that identifies this endpoint).
     */
    private suspend fun sendNewCid() {
        val cidInfo = scidRegistry.generateNew()
        val cid = cidInfo.cid().toInt()
        sendRequestQueue(Level.App).appendRequest(
            createNewConnectionIdFrame(
                cidInfo.sequenceNumber(),
                0, cid
            )
        )
    }


    override suspend fun terminate() {
        super.terminate()
        connector.removeConnection(this)

        try {
            handshakeDone.release()
        } catch (_: Throwable) {
        }



        try {
            socket?.isClosed?.let {
                if (!it) {
                    socket!!.close()
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        }

        try {
            scope.cancel()
        } catch (throwable: Throwable) {
            debug(throwable)
        }
    }

    private suspend fun runReceiver() {
        try {
            while (selectorManager.isActive) {
                val receivedPacket = socket!!.receive()
                try {
                    process(receivedPacket.packet.readByteArray())
                } catch (throwable: Throwable) {
                    debug(throwable)
                }
            }
        } catch (_: CancellationException) {
            // ignore exception
        } catch (throwable: Throwable) {
            socket?.isClosed?.let {
                if (!it) {
                    debug(throwable)
                }
            }
        } finally {
            try {
                socket?.isClosed?.let {
                    if (!it) {
                        socket!!.close()
                    }
                }
            } catch (throwable: Throwable) {
                debug(throwable)
            }
        }
    }

    private fun initialDcid(): Number {
        return dcidRegistry.initial
    }

    private suspend fun process(data: ByteArray) {
        nextPacket(Reader(data, data.size))
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun validateAndProcess(remoteTransportParameters: TransportParameters) {
        if (remoteTransportParameters.maxUdpPayloadSize < 1200) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
            return
        }
        if (remoteTransportParameters.ackDelayExponent > 20) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
            return
        }
        if (remoteTransportParameters.maxAckDelay > 16384) { // 16384 = 2^14 ()
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
            return
        }
        if (remoteTransportParameters.activeConnectionIdLimit < 2) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
            return
        }


        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-7.3
        // "An endpoint MUST treat absence of the initial_source_connection_id
        //   transport parameter from either endpoint or absence of the
        //   original_destination_connection_id transport parameter from the
        //   server as a connection error of payloadType TRANSPORT_PARAMETER_ERROR."
        if (remoteTransportParameters.initialScid == null ||
            remoteTransportParameters.originalDcid == null
        ) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
            return
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-7.3
        // "An endpoint MUST treat the following as a connection error of payloadType
        // TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:
        // a mismatch between values received from a peer in these transport parameters and the
        // value sent in the
        // corresponding Destination or Source Connection ID fields of Initial packets."
        if (initialDcid() != remoteTransportParameters.initialScid) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.PROTOCOL_VIOLATION)
            )
            return
        }

        if (originalDcid != remoteTransportParameters.originalDcid) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.PROTOCOL_VIOLATION)
            )
            return
        }


        val versionInformation = remoteTransportParameters.versionInformation
        if (versionInformation != null) {
            if (versionInformation.chosenVersion != version) {
                // https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-08.html
                // "clients MUST validate that the server's Chosen Version is equal to the negotiated version; if they do not
                //  match, the client MUST close the connection with a version negotiation error. "

                immediateCloseWithError(
                    Level.Handshake,
                    TransportError(TransportError.Code.VERSION_NEGOTIATION_ERROR)
                )
                return
            }
        }

        remoteDelayScale.store(remoteTransportParameters.ackDelayScale)


        init(
            remoteTransportParameters.initialMaxData.toLong(),
            remoteTransportParameters.initialMaxStreamDataBidiLocal.toLong(),
            remoteTransportParameters.initialMaxStreamDataBidiRemote.toLong(),
            remoteTransportParameters.initialMaxStreamDataUni.toLong()
        )


        initialMaxStreamsBidi(remoteTransportParameters.initialMaxStreamsBidi.toLong())
        initialMaxStreamsUni(remoteTransportParameters.initialMaxStreamsUni.toLong())

        remoteMaxAckDelay = remoteTransportParameters.maxAckDelay
        remoteCidLimit(remoteTransportParameters.activeConnectionIdLimit)

        determineIdleTimeout(
            transportParams.maxIdleTimeout.toLong(),
            remoteTransportParameters.maxIdleTimeout.toLong()
        )


        if (remoteTransportParameters.retrySourceConnectionId != null) {
            immediateCloseWithError(
                Level.Handshake,
                TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
            )
        }
    }


    /**
     * Register the active connection ID limit of the peer (as received by this endpoint as TP active_connection_id_limit)
     * and determine the maximum number of peer connection ID's this endpoint is willing to maintain.
     * "This is an integer value specifying the maximum number of connection IDs from the peer that an endpoint is
     * willing to store.", so it puts an upper bound to the number of connection IDs this endpoint can generate.
     */
    @OptIn(ExperimentalAtomicApi::class)
    private fun remoteCidLimit(remoteCidLimit: Int) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "An endpoint MUST NOT provide more connection IDs than the peer's limit."
        this.remoteCidLimit.store(remoteCidLimit)
    }


    /**
     * Returns the connection ID that this endpoint considers as "current".
     * Note that in QUIC, there is no such thing as a "current" connection ID, there are only active and retired
     * connection ID's. The peer can use any time any active connection ID.
     */
    override fun activeScid(): Number {
        return scidRegistry.active
    }

    /**
     * Returns the (peer's) connection ID that is currently used by this endpoint to address the peer.
     */
    override fun activeDcid(): Number {
        return dcidRegistry.active
    }


    private suspend fun validateALPN(protocols: Array<String>) {
        for (protocol in protocols) {
            if (protocol == Settings.ALPN) {
                return  // done all good
            }
        }
        immediateCloseWithError(
            Level.Handshake,
            TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
        )
    }

    private inner class StatusEventHandler : TlsStatusEventHandler {
        @OptIn(ExperimentalAtomicApi::class)
        override fun handshakeSecretsKnown() {
            // Server Hello provides a new secret, so:
            computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher())

            if (handshakeState.load().transitionAllowed(HandshakeState.HasHandshakeKeys)) {
                handshakeState.store(HandshakeState.HasHandshakeKeys)
            }

            val state = handshakeState.load()

            require(
                state == HandshakeState.HasHandshakeKeys
            ) { "Handshake state cannot be set to HasHandshakeKeys" }
        }

        @OptIn(ExperimentalAtomicApi::class)
        override suspend fun handshakeFinished() {
            // note this is not 100% correct, it discards only when handshake is finished,
            // not when the first handshake message is written [but fine for now !!!]

            // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-4.11.1
            // "Thus, a client MUST discard Initial keys when it first sends a Handshake packet (...).
            // This results in abandoning loss recovery state for the Initial encryption level and
            // ignoring any outstanding Initial packets."

            discard(Level.Initial)

            // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.1
            // -> (Thus, a client MUST discard Initial keys when it first sends a Handshake)
            // 4.9.1. Discarding Initial Keys
            // Packets protected with Initial secrets (Section 5.2) are not authenticated,
            // meaning that an attacker could spoof packets with the intent to disrupt a connection.
            // To limit these attacks, Initial packet protection keys are discarded more aggressively
            // than other keys.
            //
            // The successful use of Handshake packets indicates that no more Initial packets need to
            // be exchanged, as these keys can only be produced after receiving all CRYPTO frames from
            // Initial packets. Thus, a client MUST discard Initial keys when it first sends a
            // Handshake packet and a server MUST discard Initial keys when it first successfully
            // processes a Handshake packet. Endpoints MUST NOT send Initial packets after this point.
            //
            // This results in abandoning loss recovery state for the Initial encryption level and
            // ignoring any outstanding Initial packets.
            discardInitialKeys()


            computeApplicationSecrets(tlsEngine, tlsEngine.getSelectedCipher())

            if (handshakeState.load().transitionAllowed(HandshakeState.HasAppKeys)) {
                handshakeState.store(HandshakeState.HasAppKeys)
            }

            val state = handshakeState.load()

            require(
                state == HandshakeState.HasAppKeys
            ) { "Handshake state cannot be set to HasAppKeys" }

            state(State.Connected)

            handshakeDone.release()
        }


        override suspend fun extensionsReceived(extensions: List<Extension>) {
            for (ex in extensions) {
                when (ex) {
                    is TransportParametersExtension -> {
                        validateAndProcess(ex.transportParameters)
                    }

                    is ApplicationLayerProtocolNegotiationExtension -> {
                        validateALPN(ex.protocols)
                    }

                    else -> {
                        debug("not handled extension received $ex")
                        immediateCloseWithError(
                            Level.Handshake,
                            TransportError(TransportError.Code.TRANSPORT_PARAMETER_ERROR)
                        )
                    }
                }
            }
        }
    }

    private inner class CryptoMessageSender : ClientMessageSender {
        override suspend fun send(clientHello: ClientHello) {
            val cryptoStream = getCryptoStream(Level.Initial)
            cryptoStream.write(clientHello)
            state(State.Handshaking)
        }

        override suspend fun send(finishedMessage: FinishedMessage) {
            val cryptoStream = getCryptoStream(Level.Handshake)
            cryptoStream.write(finishedMessage)
        }

        override suspend fun send(certificateMessage: CertificateMessage) {
            val cryptoStream = getCryptoStream(Level.Handshake)
            cryptoStream.write(certificateMessage)
        }

        override suspend fun send(certificateVerifyMessage: CertificateVerifyMessage) {
            val cryptoStream = getCryptoStream(Level.Handshake)
            cryptoStream.write(certificateVerifyMessage)
        }
    }
}
