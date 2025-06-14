package io.github.remmerw.asen.quic


internal class ScidRegistry : CidRegistry(
    CidInfo(
        0,
        generateNumber(Int.SIZE_BYTES),
        CidStatus.IN_USE
    )
) {
    fun generateNew(): CidInfo {
        val sequenceNr = maxSequenceNr() + 1
        val newCid = CidInfo(
            sequenceNr,
            generateNumber(Int.SIZE_BYTES),
            CidStatus.NEW
        )
        addCid(newCid)
        return newCid
    }

    /**
     * Registers a connection id for being used.
     *
     * @return true is the connection id is new (newly used), false otherwise.
     */
    fun registerUsedConnectionId(usedCid: Number): Boolean {
        if (initial == usedCid) {
            return false
        } else {
            // Register previous connection id as used
            cidInfos()
                .filter { cid: CidInfo -> cid.cid() == initial }
                .forEach { cid: CidInfo -> cid.cidStatus(CidStatus.USED) }

            // Check if new connection id is newly used
            val wasNew = cidInfos()
                .filter { cid: CidInfo -> cid.cid() == usedCid }
                .any { cid: CidInfo -> cid.cidStatus() == CidStatus.NEW }
            // Register current connection id as current
            cidInfos()
                .filter { cid: CidInfo -> cid.cid() == usedCid }
                .forEach { cid: CidInfo -> cid.cidStatus(CidStatus.IN_USE) }

            return wasNew
        }
    }
}


