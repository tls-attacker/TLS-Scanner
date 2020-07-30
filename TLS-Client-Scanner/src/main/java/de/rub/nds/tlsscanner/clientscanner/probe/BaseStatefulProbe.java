package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;

import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseStatefulProbe<T> extends BaseProbe {

    private Map<String, T> previousStateCache;
    protected T defaultState;

    protected BaseStatefulProbe() {
        super();
        previousStateCache = new HashMap<>();
    }

    protected T getPreviousState(String raddr) {
        synchronized (previousStateCache) {
            return previousStateCache.getOrDefault(raddr, defaultState);
        }
    }

    protected void setPreviousState(String raddr, T state) {
        synchronized (previousStateCache) {
            previousStateCache.put(raddr, state);
        }
    }

    @Override
    public ClientProbeResult execute(DispatchInformation dispatchInformation) {
        String raddr = dispatchInformation.chloState.getInboundTlsContexts().get(0).getConnection().getIp();
        T previousState = getPreviousState(raddr);
        Pair<ClientProbeResult, T> ret = this.execute(previousState, dispatchInformation);
        setPreviousState(raddr, ret.getRight());
        return ret.getLeft();
    }

    protected abstract Pair<ClientProbeResult, T> execute(T previousState, DispatchInformation dispatchInformation);

}