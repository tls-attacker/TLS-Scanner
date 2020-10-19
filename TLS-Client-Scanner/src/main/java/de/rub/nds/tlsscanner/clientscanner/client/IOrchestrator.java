/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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

    public ClientProbeResult runProbe(IProbe probe, String hostnamePrefix, String uid, ClientReport report)
            throws InterruptedException, ExecutionException;
}