package de.rub.nds.tlsscanner.clientscanner.util;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BaseFuture<T> implements Future<T> {
    private static final Logger LOGGER = LogManager.getLogger();
    protected boolean done = false;
    protected T result = null;
    protected Throwable exception = null;

    @Override
    public boolean isDone() {
        return done;
    }

    @Override
    public T get() throws InterruptedException, ExecutionException {
        try {
            return get(0, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // This should never happen(tm)
            LOGGER.error("Internal error", e);
            throw new ExecutionException("An internal error occurred", e);
        }
    }

    @Override
    public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        long tTimeout = System.currentTimeMillis() + unit.toMillis(timeout);
        synchronized (this) {
            while (!done) {
                long T = System.currentTimeMillis();
                if (timeout <= 0) {
                    T = tTimeout; // wait for 0 -> infinite
                } else if (tTimeout <= T) {
                    throw new TimeoutException();
                }
                this.wait(tTimeout - T);
            }
        }
        if (exception != null) {
            throw new ExecutionException(exception);
        }
        return result;
    }

    public synchronized void setResult(T res) {
        if (done) {
            throw new IllegalStateException("Already got a result");
        }
        result = res;
        done = true;
        notifyAll();
    }

    public synchronized void setException(Throwable inner) {
        if (done) {
            throw new IllegalStateException("Already got a result");
        }
        exception = inner;
        done = true;
        notifyAll();
    }

}
