package de.rub.nds.tlsscanner.clientscanner.probe.runner;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class StatefulProbeRunner implements IProbeRunner {
    protected BaseStatefulProbe<?> probe;
    protected Orchestrator orchestrator;

    public StatefulProbeRunner(BaseStatefulProbe<?> probe, Orchestrator orchestrator) {
        this.probe = probe;
        this.orchestrator = orchestrator;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        ClientProbeResult ret = null;
        while (ret == null) {
            ret = orchestrator.runProbe(probe);
        }
        return ret;
    }

}