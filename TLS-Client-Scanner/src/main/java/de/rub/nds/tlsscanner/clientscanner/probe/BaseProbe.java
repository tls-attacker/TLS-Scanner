package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.runner.DefaultProbeRunner;
import de.rub.nds.tlsscanner.clientscanner.probe.runner.IProbeRunner;

public abstract class BaseProbe extends BaseDispatcher implements IProbe {
    @Override
    public IProbeRunner getRunner(Orchestrator orchestrator) {
        return new DefaultProbeRunner(this, orchestrator);
    }
}