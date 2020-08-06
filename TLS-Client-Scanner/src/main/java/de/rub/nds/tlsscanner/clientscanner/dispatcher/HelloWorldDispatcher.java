package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.probe.HelloWorldProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class HelloWorldDispatcher implements IDispatcher {

    private final IDispatcher probe = new HelloWorldProbe();

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) {
        return probe.execute(state, dispatchInformation);
    }

}