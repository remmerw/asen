package io.github.remmerw.asen.quic

import kotlin.concurrent.Volatile


internal class DcidRegistry(initialCid: Number) :
    CidRegistry(CidInfo(0, initialCid, CidStatus.IN_USE)) {
    @Volatile
    private var notRetiredThreshold = 0 // all sequence numbers below are retired


    /**
     * @return whether the connection id could be added as new; when its sequence number implies that it as retired already, false is returned.
     */
    fun registerNewConnectionId(sequenceNr: Int, cid: Number): Boolean {
        if (sequenceNr >= notRetiredThreshold) {
            addCid(CidInfo(sequenceNr, cid, CidStatus.NEW))
            return true
        } else {
            addCid(CidInfo(sequenceNr, cid, CidStatus.RETIRED))
            return false
        }
    }

    fun retireAllBefore(retirePriorTo: Int): List<Int> {
        notRetiredThreshold = retirePriorTo

        val toRetire: MutableList<Int> = arrayListOf()
        for (cidInfo in cidInfos()) {
            val sequenceNumber = cidInfo.sequenceNumber()
            if (sequenceNumber < retirePriorTo) {
                if (cidInfo.cidStatus() != CidStatus.RETIRED) {
                    cidInfo.cidStatus(CidStatus.RETIRED)
                    toRetire.add(sequenceNumber)
                }
            }
        }


        // Find one that is not retired
        val nextCid =
            cidInfos().firstOrNull { cid: CidInfo -> cid.cidStatus() != CidStatus.RETIRED }
        if (nextCid == null) {
            throw IllegalStateException("Can't find connection id that is not retired")
        }

        nextCid.cidStatus(CidStatus.IN_USE)


        return toRetire
    }
}

