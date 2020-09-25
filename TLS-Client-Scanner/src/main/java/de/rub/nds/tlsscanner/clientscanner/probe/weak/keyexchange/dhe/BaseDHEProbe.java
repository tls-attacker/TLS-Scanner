package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe.CipherSuiteReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public abstract class BaseDHEProbe extends BaseProbe {
    public BaseDHEProbe(IOrchestrator orchestrator) {
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
