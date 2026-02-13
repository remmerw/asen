package io.github.remmerw.asen.quic

import kotlinx.io.Buffer
import kotlinx.io.RawSink
import java.lang.Thread.yield
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.min

@Suppress("unused")
internal class Pipe {
    private val buffer = Buffer()
    private var canceled = false

    private val lock: ReentrantLock = ReentrantLock()
    private val condition: Condition = lock.newCondition()


    fun readBuffer(sink: RawSink, count: Int, timeout: Int? = null) {
        if (timeout != null) {
            source.timeout().timeout(timeout.toLong(), TimeUnit.SECONDS)
        } else {
            source.timeout().clearTimeout()
        }
        var bytes = count.toLong()
        do {
            bytes -= source.read(sink, bytes)
            yield()
        } while (bytes > 0)
    }

    val sink = object : Sink {

        override fun write(bytes: ByteArray, startIndex: Int, endIndex: Int) {
            lock.withLock {

                if (canceled) throw InterruptedException("canceled")

                buffer.write(bytes, startIndex, endIndex)
                condition.signalAll() // Notify the source that it can resume reading.

            }
        }
    }

    val source = object : Source {
        private val timeout = Timeout()

        override fun read(sink: RawSink, byteCount: Long): Long {
            lock.withLock {

                if (canceled) throw InterruptedException("canceled")

                while (buffer.size == 0L) {
                    timeout.awaitSignal(condition) // Wait until the sink fills the buffer.
                    if (canceled) throw InterruptedException("canceled")
                }

                val min = min(buffer.size, byteCount)
                buffer.readTo(sink, min)
                return min
            }
        }

        override fun timeout(): Timeout = timeout
    }


    fun close() {
        lock.withLock {
            canceled = true
            buffer.clear()
            condition.signalAll() // Notify the source and sink that they're canceled.
        }
    }
}

interface Sink {
    fun write(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size)

}

interface Source {
    /**
     * Removes at least 1, and up to `byteCount` bytes from this and appends them to `sink`. Returns
     * the number of bytes read, or -1 if this source is exhausted.
     */
    fun read(sink: RawSink, byteCount: Long): Long

    /** Returns the timeout for this source.  */
    fun timeout(): Timeout
}


open class Timeout {
    /**
     * True if `deadlineNanoTime` is defined. There is no equivalent to null or 0 for
     * [System.nanoTime].
     */
    private var hasDeadline = false
    private var deadlineNanoTime = 0L
    private var timeoutNanos = 0L


    @Volatile
    private var cancelMark: Any? = null

    /**
     * Wait at most `timeout` time before aborting an operation. Using a per-operation timeout means
     * that as long as forward progress is being made, no sequence of operations will fail.
     *
     * If `timeout == 0`, operations will run indefinitely. (Operating system timeouts may still
     * apply.)
     */
    open fun timeout(timeout: Long, unit: TimeUnit): Timeout {
        require(timeout >= 0) { "timeout < 0: $timeout" }
        timeoutNanos = unit.toNanos(timeout)
        return this
    }

    /** Returns the timeout in nanoseconds, or `0` for no timeout. */
    open fun timeoutNanos(): Long = timeoutNanos

    /** Returns true if a deadline is enabled. */
    open fun hasDeadline(): Boolean = hasDeadline

    /**
     * Returns the [nano time][System.nanoTime] when the deadline will be reached.
     *
     * @throws IllegalStateException if no deadline is set.
     */
    open fun deadlineNanoTime(): Long {
        check(hasDeadline) { "No deadline" }
        return deadlineNanoTime
    }

    /**
     * Sets the [nano time][System.nanoTime] when the deadline will be reached. All operations must
     * complete before this time. Use a deadline to set a maximum bound on the time spent on a
     * sequence of operations.
     */
    open fun deadlineNanoTime(deadlineNanoTime: Long): Timeout {
        this.hasDeadline = true
        this.deadlineNanoTime = deadlineNanoTime
        return this
    }

    /** Set a deadline of now plus `duration` time.  */
    @Suppress("unused")
    fun deadline(duration: Long, unit: TimeUnit): Timeout {
        require(duration > 0) { "duration <= 0: $duration" }
        return deadlineNanoTime(System.nanoTime() + unit.toNanos(duration))
    }

    /** Clears the timeout. Operating system timeouts may still apply. */
    open fun clearTimeout(): Timeout {
        timeoutNanos = 0
        return this
    }

    /** Clears the deadline. */

    @Suppress("unused")
    open fun clearDeadline(): Timeout {
        hasDeadline = false
        return this
    }


    /**
     * Waits on `monitor` until it is signaled. Throws [Exception] if either the thread
     * is interrupted or if this timeout elapses before `monitor` is signaled.
     * The caller must hold the lock that monitor is bound to.
     *
     * Here's a sample class that uses `awaitSignal()` to await a specific state. Note that the
     * call is made within a loop to avoid unnecessary waiting and to mitigate spurious notifications.
     *
     * ```java
     * class Dice {
     *   Random random = new Random();
     *   int latestTotal;
     *
     *   ReentrantLock lock = new ReentrantLock();
     *   Condition condition = lock.newCondition();
     *
     *   public void roll() {
     *     lock.withLock {
     *       latestTotal = 2 + random.nextInt(6) + random.nextInt(6);
     *       System.out.println("Rolled " + latestTotal);
     *       condition.signalAll();
     *     }
     *   }
     *
     *   public void rollAtFixedRate(int period, TimeUnit timeUnit) {
     *     Executors.newScheduledThreadPool(0).scheduleAtFixedRate(new Runnable() {
     *       public void run() {
     *         roll();
     *       }
     *     }, 0, period, timeUnit);
     *   }
     *
     *   public void awaitTotal(Timeout timeout, int total)
     *       throws InterruptedIOException {
     *     lock.withLock {
     *       while (latestTotal != total) {
     *         timeout.awaitSignal(this);
     *       }
     *     }
     *   }
     * }
     * ```
     */

    open fun awaitSignal(condition: Condition) {
        try {
            val hasDeadline = hasDeadline()
            val timeoutNanos = timeoutNanos()

            if (!hasDeadline && timeoutNanos == 0L) {
                condition.await() // There is no timeout: wait forever.
                return
            }

            // Compute how long we'll wait.
            val waitNanos = if (hasDeadline && timeoutNanos != 0L) {
                val deadlineNanos = deadlineNanoTime() - System.nanoTime()
                minOf(timeoutNanos, deadlineNanos)
            } else if (hasDeadline) {
                deadlineNanoTime() - System.nanoTime()
            } else {
                timeoutNanos
            }

            if (waitNanos <= 0) throw TimeoutException("timeout")

            val cancelMarkBefore = cancelMark

            // Attempt to wait that long. This will return early if the monitor is notified.
            val nanosRemaining = condition.awaitNanos(waitNanos)

            // If there's time remaining, we probably got the call we were waiting for.
            if (nanosRemaining > 0) return

            // Return without throwing if this timeout was canceled while we were waiting. Note that this
            // return is a 'spurious wakeup' because Condition.signal() was not called.
            if (cancelMark !== cancelMarkBefore) return

            throw TimeoutException("timeout")
        } catch (timeoutException: TimeoutException) {
            Thread.currentThread().interrupt() // Retain interrupted status.
            throw timeoutException
        }
    }

}
