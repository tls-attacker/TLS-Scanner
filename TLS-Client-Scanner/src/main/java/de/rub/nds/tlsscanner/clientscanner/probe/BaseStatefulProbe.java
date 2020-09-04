package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseStatefulProbe<T> extends BaseProbe {

    private Map<String, T> previousStateCache;

    public BaseStatefulProbe(IOrchestrator orchestrator) {
        super(orchestrator);
        previousStateCache = new HashMap<>();
    }

    protected abstract T getDefaultState(DispatchInformation dispatchInformation);

    protected T getPreviousState(String raddr, DispatchInformation dispatchInformation) {
        synchronized (previousStateCache) {
            if (previousStateCache.containsKey(raddr)) {
                return previousStateCache.get(raddr);
            } else {
                return getDefaultState(dispatchInformation);
            }
        }
    }

    protected void setPreviousState(String raddr, T state) {
        synchronized (previousStateCache) {
            previousStateCache.put(raddr, state);
        }
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) {
        String raddr = state.getInboundTlsContexts().get(0).getConnection().getIp();
        T previousState = getPreviousState(raddr, dispatchInformation);
        Pair<ClientProbeResult, T> ret = this.execute(state, dispatchInformation, previousState);
        setPreviousState(raddr, ret.getRight());
        return ret.getLeft();
    }

    protected abstract Pair<ClientProbeResult, T> execute(State state, DispatchInformation dispatchInformation,
            T previousState);

    @Override
    public ClientProbeResult call() throws Exception {
        ClientProbeResult ret = null;
        while (ret == null) {
            ret = super.call();
        }
        return ret;
    }
}