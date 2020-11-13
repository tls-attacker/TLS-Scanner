/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.recon;

import java.util.concurrent.Callable;

import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe.HelloReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public abstract class BaseAnalyzingProbe implements Probe {
    abstract ClientProbeResult analyzeChlo(ClientReport report, HelloReconResult chloResult);

    @Override
    public Callable<ClientProbeResult> getCallable(ClientReport report) {
        HelloReconResult chloResult = report.getResult(HelloReconProbe.class, HelloReconResult.class);
        return () -> analyzeChlo(report, chloResult);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.hasResult(HelloReconProbe.class);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        if (!report.hasResult(HelloReconProbe.class)) {
            return NotExecutedResult.MISSING_DEPENDENT_RESULT(getClass(), HelloReconProbe.class);
        }
        return NotExecutedResult.UNKNOWN_ERROR(getClass());
    }

}
