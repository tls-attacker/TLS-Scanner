package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.Queue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class ControlledClientDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    protected Queue<ResultFuture> toRun;

    public ControlledClientDispatcher() {
        toRun = new LinkedBlockingDeque<>();
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) {
        ResultFuture task;
        synchronized (toRun) {
            if (toRun.isEmpty()) {
                LOGGER.warn("Got connection but no task");
                return null;
            } else {
                task = toRun.remove();
            }
        }
        ClientProbeResult res = task.probe.execute(state, dispatchInformation);
        task.setResult(res);
        return res;
    }

    public Future<ClientProbeResult> executeProbe(IProbe probe) {
        ResultFuture ret = new ResultFuture(probe);
        synchronized (toRun) {
            toRun.add(ret);
        }
        return ret;
    }

    protected class ResultFuture implements Future<ClientProbeResult> {
        protected final IProbe probe;
        protected boolean hasResult = false;
        protected ClientProbeResult result = null;
        protected Throwable exception = null;

        public ResultFuture(IProbe probe) {
            this.probe = probe;
        }

        protected synchronized void setResult(ClientProbeResult res) {
            if (hasResult) {
                throw new IllegalStateException("Already got a result");
            }
            hasResult = true;
            result = res;
            notifyAll();
        }

        protected synchronized void setException(Throwable inner) {
            if (hasResult) {
                throw new IllegalStateException("Already got a result");
            }
            hasResult = true;
            exception = inner;
            notifyAll();
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return hasResult;
        }

        @Override
        public ClientProbeResult get() throws InterruptedException, ExecutionException {
            try {
                return get(0, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                // This should never happen:tm:
                LOGGER.error("Internal error", e);
                throw new ExecutionException("An internal error occured", e);
            }
        }

        @Override
        public ClientProbeResult get(long timeout, TimeUnit unit)
                throws InterruptedException, ExecutionException, TimeoutException {
            long tTimeout = System.currentTimeMillis() + unit.toMillis(timeout);
            synchronized (this) {
                while (!hasResult) {
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

    }

}