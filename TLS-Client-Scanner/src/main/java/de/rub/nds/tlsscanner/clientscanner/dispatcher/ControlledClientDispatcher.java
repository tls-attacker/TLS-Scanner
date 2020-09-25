package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.concurrent.Future;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.BaseFuture;
import de.rub.nds.tlsscanner.clientscanner.util.SNIUtil;

public class ControlledClientDispatcher implements IDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    protected Map<String, Queue<ClientProbeResultFuture>> toRun;
    private boolean printedNoSNIWarning = false;

    public ControlledClientDispatcher() {
        toRun = new HashMap<>();
    }

    public boolean isPrintedNoSNIWarning() {
        return printedNoSNIWarning;
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        ClientProbeResultFuture task = null;

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
            task.setGotConnection();
            dispatchInformation.additionalInformation.put(getClass(), task.clientResultFuture);
            ClientProbeResult res = task.probe.execute(state, dispatchInformation);
            task.setResult(res);
            return res;
        } catch (Exception e) {
            task.setException(e);
            throw e;
        }
    }

    protected ClientProbeResultFuture getNextTask(String name) {
        synchronized (toRun) {
            if (toRun.containsKey(name)) {
                Queue<ClientProbeResultFuture> taskQueue = toRun.get(name);
                synchronized (taskQueue) {
                    if (taskQueue.isEmpty()) {
                        return null;
                    } else {
                        ClientProbeResultFuture ret = taskQueue.remove();
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

    protected ClientProbeResultFuture getAnyNextTask() {
        synchronized (toRun) {
            for (Entry<String, Queue<ClientProbeResultFuture>> kvp : toRun.entrySet()) {
                if (!kvp.getValue().isEmpty()) {
                    ClientProbeResultFuture task = kvp.getValue().remove();
                    if (kvp.getValue().isEmpty()) {
                        toRun.remove(kvp.getKey());
                    }
                    return task;
                }
            }
        }
        return null;
    }

    public ClientProbeResultFuture enqueueProbe(IProbe probe, String expectedHostname, Future<ClientAdapterResult> clientResultHolder) {
        ClientProbeResultFuture ret = new ClientProbeResultFuture(probe, clientResultHolder);
        synchronized (toRun) {
            if (!toRun.containsKey(expectedHostname)) {
                toRun.put(expectedHostname, new LinkedList<>());
            }
            Queue<ClientProbeResultFuture> q = toRun.get(expectedHostname);
            synchronized (q) {
                q.add(ret);
            }
        }
        return ret;
    }

    public class ClientProbeResultFuture extends BaseFuture<ClientProbeResult> {
        protected final IProbe probe;
        protected final Future<ClientAdapterResult> clientResultFuture;
        protected boolean gotConnection = false;

        public ClientProbeResultFuture(IProbe probe, Future<ClientAdapterResult> clientResultFuture) {
            this.probe = probe;
            this.clientResultFuture = clientResultFuture;
        }

        protected synchronized void setGotConnection() {
            gotConnection = true;
            notifyAll();
        }

        public synchronized boolean isGotConnection() {
            return gotConnection;
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

    }

}