package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IDispatcher {
    public ClientProbeResult execute(DispatchInformation dispatchInformation);
}