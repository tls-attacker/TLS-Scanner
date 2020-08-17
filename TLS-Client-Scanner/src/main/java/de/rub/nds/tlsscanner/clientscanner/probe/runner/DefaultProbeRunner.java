package de.rub.nds.tlsscanner.clientscanner.probe.runner;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class DefaultProbeRunner implements IProbeRunner {
    protected IProbe probe;
    protected Orchestrator orchestrator;

    public DefaultProbeRunner(IProbe probe, Orchestrator orchestrator) {
        this.probe = probe;
        this.orchestrator = orchestrator;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        return orchestrator.runProbe(probe);
    }
}