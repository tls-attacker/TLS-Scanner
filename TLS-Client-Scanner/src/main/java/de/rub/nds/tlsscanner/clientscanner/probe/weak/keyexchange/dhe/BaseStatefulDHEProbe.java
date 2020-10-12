package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;

public abstract class BaseStatefulDHEProbe<T extends BaseStatefulProbe.InternalProbeState> extends BaseStatefulProbe<T> {
    private final boolean tls13, ec, ff;

    public BaseStatefulDHEProbe(IOrchestrator orchestrator, boolean tls13, boolean ec, boolean ff) {
        super(orchestrator);
        this.tls13 = tls13;
        this.ec = ec;
        this.ff = ff;
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return BaseDHEFunctionality.getRequirements(tls13, ec, ff);
    }

    public void prepareConfig(Config config) {
        BaseDHEFunctionality.prepareConfig(config, tls13, ec, ff);
    }

}
