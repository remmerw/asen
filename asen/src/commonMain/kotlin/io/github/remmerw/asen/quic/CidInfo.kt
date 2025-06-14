package io.github.remmerw.asen.quic


internal class CidInfo(
    private val sequenceNumber: Int,
    private var cid: Number,
    private var cidStatus: CidStatus
) :
    Comparable<CidInfo> {
    fun sequenceNumber(): Int {
        return sequenceNumber
    }

    fun cid(): Number {
        return cid
    }

    fun cidStatus(): CidStatus {
        return cidStatus
    }

    fun cidStatus(newStatus: CidStatus) {
        cidStatus = newStatus
    }

    override fun compareTo(other: CidInfo): Int {
        return sequenceNumber.compareTo(other.sequenceNumber)
    }

    fun cid(cid: Number) {
        this.cid = cid
    }
}

