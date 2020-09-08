package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe.CipherSuiteReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public abstract class BaseStatefulDHEProbe<T extends BaseStatefulProbe.InternalProbeState> extends BaseStatefulProbe<T> {
    public BaseStatefulDHEProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        if (!report.hasResult(CipherSuiteReconProbe.class)) {
            return false;
        }
        CipherSuiteReconResult res = report.getResult(CipherSuiteReconProbe.class, CipherSuiteReconResult.class);
        return res.supportsKeyExchangeDHE();
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        if (!report.hasResult(CipherSuiteReconProbe.class)) {
            return new NotExecutedResult(getClass(), "Missing result for CipherSuiteReconProbe");
        }
        CipherSuiteReconResult res = report.getResult(CipherSuiteReconProbe.class, CipherSuiteReconResult.class);
        if (!res.supportsKeyExchangeDHE()) {
            return new NotExecutedResult(getClass(), "Client does not support DHE");
        }
        return new NotExecutedResult(getClass(), "Internal scheduling error");
    }

}
