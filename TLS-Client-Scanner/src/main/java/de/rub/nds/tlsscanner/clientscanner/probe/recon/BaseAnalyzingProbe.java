package de.rub.nds.tlsscanner.clientscanner.probe.recon;

import java.util.concurrent.Callable;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe.HelloReconResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public abstract class BaseAnalyzingProbe implements IProbe {

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        throw new NotDispatchableException();
    }

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

    public static class NotDispatchableException extends DispatchException {
    }

}
