<div>
    <div>
        <img src="https://img.shields.io/maven-central/v/io.github.remmerw/asen" alt="Kotlin Maven Version" />
        <img src="https://img.shields.io/badge/Platform-Android-brightgreen.svg?logo=android" alt="Badge Android" />
        <img src="https://img.shields.io/badge/Platform-iOS%20%2F%20macOS-lightgrey.svg?logo=apple" alt="Badge iOS" />
        <img src="https://img.shields.io/badge/Platform-JVM-8A2BE2.svg?logo=openjdk" alt="Badge JVM" />
    </div>
</div>

## Asen

The **Asen** library implements a subset of [libp2p](https://github.com/libp2p/specs/tree/master).

It is recommended to be familiar with the technology of **libp2p** in order to
understand this documentation.

### Use-Cases

The only use-case which is supported, is the search of another peer via its peer ID.
To establish this behaviour a peer (B) which should be found, must be connected to relays
in the **libp2p** network (which are close in terms of its peer ID in a DHT).  
Another peer (B) wants to connect to peer (A), so it must know in advance its
peer ID. With this peer ID, peer (B) can connect to the same relays (like peer (A)) and establish
a connection via the relay.
Via the relay connection peer (A) receive from peer (B) its public addresses. The
relay connection is immediately closed after that.

**Limitation** The **libp2p** network protocol stack offers the possibility to establish a
direct connection between peer (A) and peer (B) via a **hole punch** mechanism. This mechanism seems
not very stable in the mobile context, so its not part of the library.

### ALPN "libp2p"

Application-Layer Protocol Negotiation (ALPN) is a Transport Layer Security (TLS) extension that
allows the application layer to negotiate which protocol should be performed over a secure
connection. This library support the ALPN **libp2p**.

The library support the following protocols of the ALPN **libp2p**

- /multistream/1.0.0
- /libp2p/circuit/relay/0.2.0/stop
- /libp2p/circuit/relay/0.2.0/hop
- /ipfs/kad/1.0.0
- /ipfs/id/1.0.0

### Certificate

The certificate, which is required for a TLS handshake during a connection process, is described
in [TLS Handshake](https://github.com/libp2p/specs/blob/master/tls/tls.md).
The self-signed certificate is used to verify each others peer Ids.

### Limitations

This sections contains the limitations of the library. The limitations are in general by design.

#### IP Version

Only IPv6 are supported, due to the fact that a direct connection of an IPv6 node to an IPv4 node is
not possible.

#### Protocols

The **ping**, **autonat**, **bitswap** and **pubsub**  and other protocols are not in the scope
of this library. [**Limitation by Design**]

#### Crypto

This library works only with **Ed25519** keys and only those will be supported. The keys are used
for signing own content (e.g. Certificate) and used for identification (PeerId, Peeraddr).

#### Transport

Only QUIC will be supported for transport, because of performance. [**Limitation by Design**]

#### MDNS

Not supported and it is not be considered to be part of the library. [**Limitation by Design**]

#### UPNP

Not supported and it is not be considered to be part of the library. [**Limitation by Design**]


## Integration

```
    
kotlin {
    sourceSets {
        commonMain.dependencies {
            ...
            implementation("io.github.remmerw:asen:0.3.0")
        }
        ...
    }
}
    
```

## API

### General

The main functionality of the **Asen** library is available through the **io.github.remmerw.asen.Asen**
class.

```

// generate the default required Ed25519 keys (PeerId and privateKey)
// Note: a PeerId is a Ed25519 public key 
val keys : Keys = generateKeys(); // generate new keys 

// bootstrap addresses for the DHT
val bootstrap = Peeraddrs();
bootstrap.add(...); // add a valid bootstrap address

val asen = newAsen(keys = keys, bootstrap = bootstrap, blockStore = blockstore)


// -> or the shortform, which does the same settings
val asen = newAsen(bootstrap= bootstrap)



### All options


/**
 * Create a new Asen instance
 *
 * @param keys public and private ed25519 keys for the peer ID, signing, verification and authentication
 * @param bootstrap initial bootstrap peers for the DHT (without bootstrap peers it can only be used for testing)
 * @param peerStore additional DHT peers (note the list will be filled and readout)
 */
fun newAsen(
    keys: Keys = generateKeys(),
    bootstrap: List<Peeraddr> = bootstrap(),
    peerStore: PeerStore = MemoryPeers()
): Asen {
...
}

```

#### Peer Store

This section describes the peer storage within this library.
Primarily it is used for storing peer within the **DHT** (**/ipfs/kad/1.0.0**) to fulfill its
functionality.

The default peer store implementation is represented by the class **MemoryPeers**.

```
interface PeerStore {
    suspend fun peeraddrs(limit: Int): List<Peeraddr>

    suspend fun store(peeraddr: Peeraddr)
}
```

### Find Peer

This section describes how to find a peer via relays in a **libp2p2** network.

To find a peer the ID of the peer is required (peerId). A peerId is a a 32 bit Ed25519 public key,
which will also be used for signing content and authentication.

```
    /**
     * Find the peer addresses of given target peer ID via the **libp2p** relay mechanism.
     *
     * @param target the target peer ID which addresses should be retrieved
     * @param timeout in seconds
     * @return list of the peer addresses (usually one IPv6 address)
     */
     suspend fun findPeer(target: PeerId, timeout: Long): List<Peeraddr> {
         ...
    }
```

### Reservation

This section describes how to monitor and initiate a reservation on relays.

A reservation to a relay is required, so that your node might be accessible by others nodes.

Documentation of relays are documented
under [circuit-v2](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md#introduction).

```
     /**
     * Makes a reservation o relay nodes with the purpose that other peers can fin you via
     * the nodes peerId
     *
     * @param peeraddrs the peeraddrs which should be announced to incoming connecting peers via relays
     * @param maxReservation number of max reservations
     * @param timeout in seconds
     */
    suspend fun makeReservations(
        peeraddrs: List<Peeraddr>,
        maxReservation: Int,
        timeout: Int
    ) {
        ...
    }
    
    /**
     * Returns all currently connected relays as a list of peer addresses
     *
     * @return list of relay peer addresses
     */
    fun reservations(): Peeraddrs {
        ...
    }

    fun hasReservations(): Boolean {
        ...
    }
    
    fun numReservations(): Int {
        ...
    }
```

## Example

```
    @Test
    fun testConnection(): Unit = runBlocking(Dispatchers.IO) {

        val bob = newAsen()
        val alice = newAsen()

        // Use Case : alice wants to connect to bob
        // [1] bob has to make reservations to relays
        val publicAddresses = listOf(
            
            // artificial address where the "data" server of bob is running
            Peeraddr(
                bob.peerId(),
                bob.publicAddress()!!,
                5001.toUShort()
            )
        )

        // Note: bob has a service running on port 5001
        bob.makeReservations(
            publicAddresses,
            20,
            120
        )  // timeout max 2 min (120 s) or 20 relays

        assertTrue(bob.hasReservations())

        // [2] alice can find bob via its peerId
        val peeraddrs = alice.findPeer(bob.peerId(), 120)  // timeout max 2 min (120 s)


        // testing
        assertNotNull(peeraddrs) // peeraddrs are the public IP addresses
        assertTrue(peeraddrs.isNotEmpty())

        val address = peeraddrs.first()
        assertEquals(address.peerId, bob.peerId())

        bob.shutdown()
        alice.shutdown()
    }

```
