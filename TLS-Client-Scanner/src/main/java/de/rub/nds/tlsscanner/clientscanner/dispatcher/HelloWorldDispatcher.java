package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsscanner.clientscanner.probe.HelloWorldProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class HelloWorldDispatcher implements IDispatcher {

    private final HelloWorldProbe probe = new HelloWorldProbe();

    @Override
    public ClientProbeResult execute(DispatchInformation dispatchInformation) {
        return probe.execute(dispatchInformation);
    }

}