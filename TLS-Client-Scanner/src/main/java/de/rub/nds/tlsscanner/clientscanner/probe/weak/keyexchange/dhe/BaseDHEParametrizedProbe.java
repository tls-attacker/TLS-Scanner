/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

public abstract class BaseDHEParametrizedProbe<T extends Enum<T>, R> extends BaseDHEProbe {
    protected final T enumValue;

    public BaseDHEParametrizedProbe(IOrchestrator orchestrator, boolean tls13, boolean ec, boolean ff, T value) {
        super(orchestrator, tls13, ec, ff);
        this.enumValue = value;
    }

    @Override
    protected String getHostnamePrefix() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.enumValue.name());
        sb.append('.');
        sb.append(super.getHostnamePrefix());
        return sb.toString();
    }

    @Override
    public final ClientProbeResult execute(State state, DispatchInformation dispatchInformation)
            throws DispatchException {
        R res = executeInternal(state, dispatchInformation);
        return new ParametrizedClientProbeResult<T, R>(getClass(), enumValue, res);
    }

    protected abstract R executeInternal(State state, DispatchInformation dispatchInformation) throws DispatchException;

}
