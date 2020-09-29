package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseDHEProbe extends BaseProbe {
    private final boolean tls13, ec, ff;

    public BaseDHEProbe(IOrchestrator orchestrator, boolean tls13, boolean ec, boolean ff) {
        super(orchestrator);
        this.tls13 = tls13;
        this.ec = ec;
        this.ff = ff;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return BaseDHEFunctionality.canBeExecuted(report, tls13, ec, ff);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return BaseDHEFunctionality.getCouldNotExecuteResult(getClass(), report, tls13, ec, ff);
    }

    public void prepareConfig(Config config) {
        BaseDHEFunctionality.prepareConfig(config, tls13, ec, ff);
    }

}
