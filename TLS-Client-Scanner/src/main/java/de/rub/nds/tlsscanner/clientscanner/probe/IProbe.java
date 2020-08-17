package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.runner.IProbeRunner;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IProbe extends IDispatcher {

    /**
     * Whether it makes sense to execute this probe given the current report.
     *
     * @param report
     *                   The report so far
     * @return Whether it makes sense to execute this probe.
     */
    public boolean canBeExecuted(ClientReport report);

    public ClientProbeResult getCouldNotExecuteResult();

    public IProbeRunner getRunner(Orchestrator orchestrator);
}