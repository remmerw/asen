@file:Suppress("unused")

package io.github.remmerw.asen.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.protobuf.ProtoNumber

/*

message HopMessage {
  enum Type {
    RESERVE = 0;
    CONNECT = 1;
    STATUS = 2;
  }

  // This field is marked optional for backwards compatibility with proto2.
  // Users should make sure to always set this.
  Type type = 1;

  Peer peer = 2;
  Reservation reservation = 3;
  Limit limit = 4;

  Status status = 5;
}

message StopMessage {
  enum Type {
    CONNECT = 0;
    STATUS = 1;
  }

  // This field is marked optional for backwards compatibility with proto2.
  // Users should make sure to always set this.
  Type type = 1;

  Peer peer = 2;
  Limit limit = 3;

  Status status = 4;
}

message Peer {
  // This field is marked optional for backwards compatibility with proto2.
  // Users should make sure to always set this.
  bytes id = 1;
  repeated bytes addrs = 2;
}

message Reservation {
  // This field is marked optional for backwards compatibility with proto2.
  // Users should make sure to always set this.
  uint64 expire = 1; // Unix expiration time (UTC)
  repeated bytes addrs = 2;   // relay addrs for reserving peer
  bytes voucher = 3; // reservation voucher
}

message Limit {
  uint32 duration = 1; // seconds
  uint64 data = 2;     // bytes
}

enum Status {
  // zero value field required for proto3 compatibility
  UNUSED = 0;
  OK = 100;
  RESERVATION_REFUSED = 200;
  RESOURCE_LIMIT_EXCEEDED = 201;
  PERMISSION_DENIED = 202;
  CONNECTION_FAILED = 203;
  NO_RESERVATION = 204;
  MALFORMED_MESSAGE = 400;
  UNEXPECTED_MESSAGE = 401;
}
 */

@Serializable
data class HopMessage(
    val type: Type? = null,
    val peer: Peer? = null,
    val reservation: Reservation? = null,
    val limit: Limit? = null,
    val status: Status? = null
) {

    @Serializable
    enum class Type {
        RESERVE,
        CONNECT,
        STATUS
    }
}

@Serializable
data class StopMessage(
    val type: Type? = null,
    val peer: Peer? = null,
    val limit: Limit? = null,
    val status: Status? = null
) {

    @Serializable
    enum class Type {
        CONNECT,
        STATUS
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
enum class Status {
    @Suppress("unused")
    @ProtoNumber(0)
    UNUSED,

    @ProtoNumber(100)
    OK,

    @Suppress("unused")
    @ProtoNumber(200)
    RESERVATION_REFUSED,

    @Suppress("unused")
    @ProtoNumber(201)
    RESOURCE_LIMIT_EXCEEDED,

    @ProtoNumber(202)
    PERMISSION_DENIED,

    @Suppress("unused")
    @ProtoNumber(203)
    CONNECTION_FAILED,

    @Suppress("unused")
    @ProtoNumber(204)
    NO_RESERVATION,

    @ProtoNumber(400)
    MALFORMED_MESSAGE,

    @ProtoNumber(401)
    UNEXPECTED_MESSAGE
}

@Serializable
data class Limit(
    val duration: Int? = null,
    val data: Long? = null
)

@Serializable
data class Reservation(
    val expire: Long? = null,
    val addrs: List<ByteArray> = emptyList(),
    val voucher: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Reservation

        if (expire != other.expire) return false
        if (addrs != other.addrs) return false
        if (!voucher.contentEquals(other.voucher)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = expire?.hashCode() ?: 0
        result = 31 * result + addrs.hashCode()
        result = 31 * result + (voucher?.contentHashCode() ?: 0)
        return result
    }

}

@Serializable
data class Peer(val id: ByteArray, val addrs: List<ByteArray> = emptyList()) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Peer

        if (!id.contentEquals(other.id)) return false
        if (addrs != other.addrs) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + addrs.hashCode()
        return result
    }


}