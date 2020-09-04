package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHWeakPrivateKeyProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class HelloWorldDispatcher implements IDispatcher {

    private final IDispatcher probe = new DHWeakPrivateKeyProbe(null);

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        return probe.execute(state, dispatchInformation);
    }

}