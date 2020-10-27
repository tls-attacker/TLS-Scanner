/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import javax.naming.OperationNotSupportedException;

import org.bouncycastle.asn1.eac.BidirectionalMap;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIUidDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIUidDispatcher.UidInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BaseStatefulProbe<T extends BaseStatefulProbe.InternalProbeState> extends BaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();
    // map UID to state
    private Map<String, T> previousStateCache;

    public BaseStatefulProbe(IOrchestrator orchestrator) {
        super(orchestrator);
        previousStateCache = new HashMap<>();
    }

    // #region serving side

    protected abstract T getDefaultState();

    protected T getPreviousState(String uid) {
        synchronized (previousStateCache) {
            if (previousStateCache.containsKey(uid)) {
                return previousStateCache.get(uid);
            } else {
                return getDefaultState();
            }
        }
    }

    protected void setPreviousState(String uid, T state) {
        synchronized (previousStateCache) {
            previousStateCache.put(uid, state);
        }
    }

    protected void removePreviousState(String uid) {
        synchronized (previousStateCache) {
            previousStateCache.remove(uid);
        }
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        String uid;
        if (dispatchInformation.additionalInformation.containsKey(SNIUidDispatcher.class)) {
            uid = dispatchInformation.getAdditionalInformation(SNIUidDispatcher.class, UidInformation.class).uid;
        } else {
            String raddr = state.getInboundTlsContexts().get(0).getConnection().getIp();
            // report only generates alphanumeric uids - we can simply include a
            // non
            // alphanum char (e.g. ':') to not interfere with them
            uid = "RADDR:" + raddr;
            if (!previousStateCache.containsKey(uid)) {
                // issue warning only once (per addr and, unfortunately, probe)
                LOGGER.warn("Could not find UID for remote address {} (most likely due to no SNI)", raddr);
            }
        }
        T previousState = getPreviousState(uid);
        T ret = this.execute(state, dispatchInformation, previousState);
        if (ret.isDone()) {
            removePreviousState(uid);
            ClientProbeResult res = ret.toResult();
            if (res == null) {
                throw new DispatchException("Got null result, even though probe said it was done");
            }
            return res;
        } else {
            setPreviousState(uid, ret);
            return null;
        }
    }

    protected abstract T execute(State state, DispatchInformation dispatchInformation,
            T internalState) throws DispatchException;

    // #endregion

    // #region Orchestrating side
    @Override
    @SuppressWarnings("squid:S4274")
    // sonarlint: use assert to check parameters
    // in this case we do not care about the parameter at all. This is just to
    // help check whether it was programmed correctly
    protected ClientProbeResult callInternal(ClientReport report, String nullString) throws InterruptedException,
            ExecutionException {
        // the nullString would be the getHostnamePrefix()
        // but as we return null there, it shall be null
        assert nullString == null;
        ClientProbeResult ret = null;
        while (ret == null) {
            T internalState = getPreviousState(report.uid);
            ret = super.callInternal(report, getHostnamePrefix(internalState));
        }
        return ret;
    }

    public static interface InternalProbeState {
        boolean isDone();

        ClientProbeResult toResult();
    }

    @Override
    protected final String getHostnamePrefix() {
        return null;
    }

    protected String getHostnamePrefix(T internalState) {
        return super.getHostnamePrefix();
    }
    // #endregion
}