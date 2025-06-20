/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.scan;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Extends {@link ThreadPoolExecutor} with its own afterExecute function. A
 * ScannerThreadPoolExecutor hold a semaphore which is released each time a Thread finished
 * executing.
 */
public class ScannerThreadPoolExecutor extends ScheduledThreadPoolExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final RejectedExecutionHandler defaultHandler = new AbortPolicy();

    private final Semaphore semaphore;

    /** The time after which tasks are automatically cancelled */
    private final long timeout;

    /**
     * Creates a new ScannerThreadPoolExecutor with the specified core pool size, thread factory,
     * semaphore, and timeout. The executor will automatically cancel tasks that exceed the timeout
     * duration.
     *
     * @param corePoolSize the number of threads to keep in the pool
     * @param threadFactory the factory to use when creating new threads
     * @param semaphore the semaphore to be released after each task execution
     * @param timeout the timeout after which tasks are cancelled in milliseconds
     */
    public ScannerThreadPoolExecutor(
            int corePoolSize, ThreadFactory threadFactory, Semaphore semaphore, long timeout) {
        super(corePoolSize, threadFactory, defaultHandler);
        this.semaphore = semaphore;
        this.timeout = timeout;
    }

    /**
     * Releases the semaphore when the Runnable r finished executing.
     *
     * @param r The runnable that finished executing.
     * @param t Should r fail, t holds the exception.
     */
    @Override
    protected void afterExecute(Runnable r, Throwable t) {
        semaphore.release();
    }

    /**
     * Submits a Runnable task for execution and returns a Future representing that task. The task
     * will be automatically cancelled if it does not complete within the configured timeout period.
     *
     * @param task the task to submit
     * @return a Future representing pending completion of the task
     */
    @Override
    public Future<?> submit(Runnable task) {
        Future<?> future = super.submit(task);
        cancelFuture(future);
        return future;
    }

    /**
     * Submits a Runnable task for execution and returns a Future representing that task. The task
     * will be automatically cancelled if it does not complete within the configured timeout period.
     *
     * @param <T> the type of the result
     * @param task the task to submit
     * @param result the result to return
     * @return a Future representing pending completion of the task
     */
    @Override
    public <T> Future<T> submit(Runnable task, T result) {
        Future<T> future = super.submit(task, result);
        cancelFuture(future);
        return future;
    }

    /**
     * Submits a value-returning task for execution and returns a Future representing the pending
     * results of the task. The task will be automatically cancelled if it does not complete within
     * the configured timeout period.
     *
     * @param <T> the type of the task's result
     * @param task the task to submit
     * @return a Future representing pending completion of the task
     */
    @Override
    public <T> Future<T> submit(Callable<T> task) {
        Future<T> future = super.submit(task);
        cancelFuture(future);
        return future;
    }

    private void cancelFuture(Future<?> future) {
        this.schedule(
                new Runnable() {
                    public void run() {
                        if (!future.isDone()) {
                            future.cancel(true);
                            if (future.isCancelled()) {
                                LOGGER.error("Killed task ", future);
                            } else {
                                LOGGER.error("Could not kill task ", future);
                            }
                        } else {
                            LOGGER.debug("Future already done! ", future);
                        }
                        semaphore.release();
                    }
                },
                timeout,
                TimeUnit.MILLISECONDS);
    }
}
