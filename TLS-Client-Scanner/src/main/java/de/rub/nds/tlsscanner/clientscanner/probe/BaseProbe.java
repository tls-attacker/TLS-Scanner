package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseProbe extends BaseDispatcher implements IProbe {
    private Orchestrator orchestrator;

    public BaseProbe(Orchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        return orchestrator.runProbe(this);
    }
}