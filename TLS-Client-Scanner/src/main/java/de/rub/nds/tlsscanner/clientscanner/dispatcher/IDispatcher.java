package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IDispatcher {
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation);
}