package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseProbe extends BaseDispatcher implements IProbe {
    private IOrchestrator orchestrator;

    public BaseProbe(IOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        return orchestrator.runProbe(this);
    }
}