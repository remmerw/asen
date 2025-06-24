package io.github.remmerw.asen.quic

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock


internal class SendRequestQueue {
    private val requestQueue: ArrayDeque<SendRequest> = ArrayDeque()
    private val mutex = Mutex()

    suspend fun appendRequest(fixedFrame: Frame) {
        mutex.withLock {
            requestQueue.addLast(
                SendRequest(
                    fixedFrame.frameLength(),
                    object : FrameSupplier {
                        override suspend fun nextFrame(maxSize: Int): Frame? {
                            return fixedFrame
                        }
                    }
                ))
        }
    }

    suspend fun insertRequest(fixedFrame: Frame) {
        mutex.withLock {
            requestQueue.addFirst(
                SendRequest(
                    fixedFrame.frameLength(), object : FrameSupplier {
                        override suspend fun nextFrame(maxSize: Int): Frame? {
                            return fixedFrame
                        }
                    }
                )
            )
        }
    }

    /**
     * @param estimatedSize The minimum size of the frame that the supplier can produce. When the supplier is
     * requested to produce a frame of that size, it must return a frame of the size or smaller.
     * This leaves room for the caller to handle uncertainty of how large the frame will be,
     * for example due to a var-length int value that may be larger at the moment the frame
     */
    suspend fun appendRequest(frameSupplier: FrameSupplier, estimatedSize: Int) {
        mutex.withLock {
            requestQueue.addLast(SendRequest(estimatedSize, frameSupplier))
        }
    }

    suspend fun hasRequests(): Boolean {
        mutex.withLock {
            return !requestQueue.isEmpty()
        }
    }


    suspend fun next(maxFrameLength: Int): SendRequest? {
        if (maxFrameLength < 1) {  // Minimum frame size is 1: some frames (e.g. ping) are just a payloadType field.
            // Forget it
            return null
        }

        mutex.withLock {
            val iterator = requestQueue.iterator()
            while (iterator.hasNext()) {
                val next = iterator.next()
                if (next.estimatedSize <= maxFrameLength) {
                    iterator.remove()
                    return next
                }
            }
        }
        // Couldn't find one.
        return null
    }

    suspend fun clear() {
        mutex.withLock {
            requestQueue.clear()
        }
    }
}

