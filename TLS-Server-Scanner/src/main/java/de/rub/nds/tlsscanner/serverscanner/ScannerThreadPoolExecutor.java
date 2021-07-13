package de.rub.nds.tlsscanner.serverscanner;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Extends {@link ThreadPoolExecutor} with its own afterExecute function.
 * A ScannerThreadPoolExecutor hold a semaphore which is released each time a
 * Thread finished executing.
 */
public class ScannerThreadPoolExecutor extends ThreadPoolExecutor {

    private static final RejectedExecutionHandler defaultHandler =
            new AbortPolicy();

    private final Semaphore semaphore;

    /**
     * Call super and assign the semaphore
     */
    public ScannerThreadPoolExecutor(int corePoolSize,
                                     int maximumPoolSize,
                                     long keepAliveTime,
                                     TimeUnit unit,
                                     BlockingQueue<Runnable> workQueue,
                                     ThreadFactory threadFactory,
                                     Semaphore semaphore) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue,
                threadFactory, defaultHandler);
        this.semaphore = semaphore;
    }

    /**
     * Releases the semaphore when the Runnable r finished executing.
     * @param r The runnable that finished executing.
     * @param t Should r fail, t holds the exception.
     */
    @Override
    protected void afterExecute(Runnable r, Throwable t) {
        semaphore.release();
    }
}
