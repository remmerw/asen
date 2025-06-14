package io.github.remmerw.asen.quic

import kotlinx.atomicfu.locks.reentrantLock
import kotlinx.atomicfu.locks.withLock


internal class SendRequestQueue {
    private val requestQueue: ArrayDeque<SendRequest> = ArrayDeque()
    private val lock = reentrantLock()

    fun appendRequest(fixedFrame: Frame) {
        lock.withLock {
            requestQueue.addLast(
                SendRequest(
                    fixedFrame.frameLength(),
                    object : FrameSupplier {
                        override fun nextFrame(maxSize: Int): Frame? {
                            return fixedFrame
                        }
                    }
                ))
        }
    }

    fun insertRequest(fixedFrame: Frame) {
        lock.withLock {
            requestQueue.addFirst(
                SendRequest(
                    fixedFrame.frameLength(), object : FrameSupplier {
                        override fun nextFrame(maxSize: Int): Frame? {
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
    fun appendRequest(frameSupplier: FrameSupplier, estimatedSize: Int) {
        lock.withLock {
            requestQueue.addLast(SendRequest(estimatedSize, frameSupplier))
        }
    }

    fun hasRequests(): Boolean {
        lock.withLock {
            return !requestQueue.isEmpty()
        }
    }


    fun next(maxFrameLength: Int): SendRequest? {
        if (maxFrameLength < 1) {  // Minimum frame size is 1: some frames (e.g. ping) are just a payloadType field.
            // Forget it
            return null
        }

        lock.withLock {
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

    fun clear() {
        lock.withLock {
            requestQueue.clear()
        }
    }
}

