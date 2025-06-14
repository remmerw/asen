@file:Suppress("unused")

package io.github.remmerw.asen.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.protobuf.ProtoNumber

/* proto definition
// In order to re-generate the golang packages for `Message` you will need...
// 1. Protobuf binary (tested with protoc 3.0.0). - https://github.com/gogo/protobuf/releases
// 2. Gogo Protobuf (tested with gogo 0.3). - https://github.com/gogo/protobuf
// 3. To have cloned `libp2p/go-libp2p-{record,kad-dht}` under the same directory.
// Now from `libp2p/go-libp2p-kad-dht/pb` you can run...
// `protoc --gogo_out=. --proto_path=../../go-libp2p-record/pb/ --proto_path=./ dht.proto`


syntax = "proto3";


message Message {
  enum MessageType {
    PUT_VALUE = 0;  // not supported in Asen
    GET_VALUE = 1;  // not supported in Asen
    ADD_PROVIDER = 2;
    GET_PROVIDERS = 3;
    FIND_NODE = 4;
    PING = 5; // not supported in Asen
  }

  enum ConnectionType {
    // sender does not have a connection to peer, and no extra information (default)
    NOT_CONNECTED = 0;

    // sender has a live connection to peer
    CONNECTED = 1;

    // sender recently connected to peer
    CAN_CONNECT = 2;

    // sender recently tried to connect to peer repeatedly but failed to connect
    // ("try" here is loose, but this should signal "made strong effort, failed")
    CANNOT_CONNECT = 3;
  }

  message Peer {
    // ID of a given peer.
    bytes id = 1;

    // multiaddrs for a given peer
    repeated bytes addrs = 2;

    // used to signal the sender's connection capabilities to the peer
    ConnectionType connection = 3;
  }

  // defines what type of message it is.
  MessageType type = 1;

  // defines what coral cluster level this query/response belongs to.
  // in case we want to implement coral's cluster rings in the future.
  // int32 clusterLevelRaw = 10; // not supported in Asen

  // Used to specify the key associated with this message.
  // PUT_VALUE, GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
  bytes key = 2;

  // Used to return a value
  // PUT_VALUE, GET_VALUE
  // record.pb.Record record = 3; // not supported in Asen

  // Used to return peers closer to a key in a query
  // GET_VALUE, GET_PROVIDERS, FIND_NODE
  repeated Peer closerPeers = 8;

  // Used to return Providers
  // GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
  repeated Peer providerPeers = 9;
}
*/

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class Message(
    val type: MessageType,
    val key: ByteArray? = null,
    @ProtoNumber(8)
    val closerPeers: List<Peer> = emptyList(),
    @ProtoNumber(9)
    val providerPeers: List<Peer> = emptyList()
) {


    @Serializable
    enum class MessageType {
        @Suppress("unused")
        PUT_VALUE,

        @Suppress("unused")
        GET_VALUE,

        @Suppress("unused")
        ADD_PROVIDER,

        @Suppress("unused")
        GET_PROVIDERS,

        FIND_NODE,

        @Suppress("unused")
        PING
    }

    @Suppress("unused")
    @Serializable
    enum class ConnectionType {
        // sender does not have a connection to peer, and no extra information (default)
        NOT_CONNECTED,

        // sender has a live connection to peer
        CONNECTED,

        // sender recently connected to peer
        CAN_CONNECT,

        // sender recently tried to connect to peer repeatedly but failed to connect
        // ("try" here is loose, but this should signal "made strong effort, failed")
        CANNOT_CONNECT
    }


    @Serializable
    data class Peer(
        val id: ByteArray,
        val addrs: List<ByteArray> = emptyList(),
        val connection: ConnectionType? = null
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Peer

            if (!id.contentEquals(other.id)) return false
            if (addrs != other.addrs) return false
            if (connection != other.connection) return false

            return true
        }

        override fun hashCode(): Int {
            var result = id.contentHashCode()
            result = 31 * result + addrs.hashCode()
            result = 31 * result + (connection?.hashCode() ?: 0)
            return result
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Message

        if (type != other.type) return false
        if (!key.contentEquals(other.key)) return false
        if (closerPeers != other.closerPeers) return false
        if (providerPeers != other.providerPeers) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (key?.contentHashCode() ?: 0)
        result = 31 * result + closerPeers.hashCode()
        result = 31 * result + providerPeers.hashCode()
        return result
    }


}