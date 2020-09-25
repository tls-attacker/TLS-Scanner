package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseStatefulDHEProbe<T extends BaseStatefulProbe.InternalProbeState> extends BaseStatefulProbe<T> {
    public BaseStatefulDHEProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return BaseDHEFunctionality.canBeExecuted(report);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return BaseDHEFunctionality.getCouldNotExecuteResult(getClass(), report);
    }

}
