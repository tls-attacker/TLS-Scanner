package de.rub.nds.tlsscanner.clientscanner.client;

import java.util.concurrent.ExecutionException;

import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IOrchestrator {
    public ClientInfo getReportInformation();

    public void start();

    public void cleanup();

    public void postProcessing(ClientReport report);

    public ClientProbeResult runProbe(IProbe probe)
            throws InterruptedException, ExecutionException;

    public ClientProbeResult runProbe(IProbe probe, String hostnamePrefix)
            throws InterruptedException, ExecutionException;
}