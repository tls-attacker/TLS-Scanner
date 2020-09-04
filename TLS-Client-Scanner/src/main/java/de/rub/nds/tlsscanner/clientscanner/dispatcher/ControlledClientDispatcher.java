package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.SNIUtil;

public class ControlledClientDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    protected Map<String, Queue<ResultFuture>> toRun;
    private boolean printedNoSNIWarning = false;

    public ControlledClientDispatcher() {
        toRun = new HashMap<>();
    }

    public boolean isPrintedNoSNIWarning() {
        return printedNoSNIWarning;
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        ResultFuture task = null;

        ServerNameIndicationExtensionMessage SNI = SNIUtil
                .getSNIFromExtensions(dispatchInformation.chlo.getExtensions());
        if (SNI != null || toRun.containsKey(null)) {
            String name = SNIUtil.getServerNameFromSNIExtension(SNI);
            task = getNextTask(name);
            if (task == null) {
                LOGGER.warn("Got hostname which we do not have a task for {}", name);
            }
        } else {
            if (!printedNoSNIWarning) {
                printedNoSNIWarning = true;
                LOGGER.warn(
                        "Got no SNI - If the runner is using multiple threads this may cause issues as hostnames may not be matched to probes correctly");
            }
            // pick any probe
            task = getAnyNextTask();
            if (task == null) {
                LOGGER.warn("Got no tasks left (NO SNI)");
            }
        }
        if (task == null) {
            return null;
        }
        try {
            ClientProbeResult res = task.probe.execute(state, dispatchInformation);
            task.setResult(res);
            return res;
        } catch (Exception e) {
            task.setException(e);
            throw e;
        }
    }

    protected ResultFuture getNextTask(String name) {
        synchronized (toRun) {
            if (toRun.containsKey(name)) {
                Queue<ResultFuture> taskQueue = toRun.get(name);
                synchronized (taskQueue) {
                    if (taskQueue.isEmpty()) {
                        return null;
                    } else {
                        ResultFuture ret = taskQueue.remove();
                        if (taskQueue.isEmpty()) {
                            toRun.remove(name);
                        }
                        return ret;
                    }
                }
            } else {
                return null;
            }
        }
    }

    protected ResultFuture getAnyNextTask() {
        synchronized (toRun) {
            for (Entry<String, Queue<ResultFuture>> kvp : toRun.entrySet()) {
                if (!kvp.getValue().isEmpty()) {
                    ResultFuture task = kvp.getValue().remove();
                    if (kvp.getValue().isEmpty()) {
                        toRun.remove(kvp.getKey());
                    }
                    return task;
                }
            }
        }
        return null;
    }

    public Future<ClientProbeResult> enqueueProbe(IProbe probe, String expectedHostname) {
        ResultFuture ret = new ResultFuture(probe);
        synchronized (toRun) {
            if (!toRun.containsKey(expectedHostname)) {
                toRun.put(expectedHostname, new LinkedList<>());
            }
            Queue<ResultFuture> q = toRun.get(expectedHostname);
            synchronized (q) {
                q.add(ret);
            }
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
            result = res;
            hasResult = true;
            notifyAll();
        }

        protected synchronized void setException(Throwable inner) {
            if (hasResult) {
                throw new IllegalStateException("Already got a result");
            }
            exception = inner;
            hasResult = true;
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