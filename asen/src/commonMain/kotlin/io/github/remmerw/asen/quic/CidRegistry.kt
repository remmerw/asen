package io.github.remmerw.asen.quic

internal open class CidRegistry(init: CidInfo) {
    private val cidInfos: MutableList<CidInfo> = mutableListOf(init)

    fun initialConnectionId(cid: Number) {
        cidInfos.first().cid(cid)
    }

    fun maxSequenceNr(): Int {
        val last = cidInfos.maxOrNull()
        if (last != null) {
            return last.sequenceNumber()
        }
        return 0
    }

    fun addCid(cidInfo: CidInfo) {
        cidInfos.add(cidInfo)
    }

    fun retireCid(sequenceNr: Int): Int? {
        val cidInfo = cidInfo(sequenceNr)
        if (cidInfo != null) {
            if (cidInfo.cidStatus().active()) {
                cidInfo.cidStatus(CidStatus.RETIRED)
                require(cidInfo.cid() is Int) { "Invalid number" }
                return cidInfo.cid() as Int
            }
        }
        return null
    }


    fun cidInfo(sequenceNr: Int): CidInfo? {
        for (cidInfo in cidInfos) {
            if (cidInfo.sequenceNumber() == sequenceNr) {
                return cidInfo
            }
        }
        return null
    }


    val initial: Number
        get() = cidInfos.first().cid()

    val active: Number
        /**
         * Get an active connection ID. There can be multiple active connection IDs, this method returns an arbitrary one.
         *
         * @return an active connection ID or null if non is active (which should never happen).
         */
        get() {
            for (info in cidInfos) {
                if (info.cidStatus().active()) {
                    return info.cid()
                }
            }
            throw IllegalStateException("no active connection id")
        }


    val activeCids: Int
        get() {
            var active = 0
            for (info in cidInfos) {
                if (info.cidStatus().active()) {
                    active++
                }
            }
            return active
        }


    fun cidInfos(): List<CidInfo> {
        return cidInfos.sorted()
    }
}

