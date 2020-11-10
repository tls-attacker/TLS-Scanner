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
import java.util.concurrent.ExecutorService;

import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface Orchestrator {
    ClientScannerConfig getCSConfig();

    ClientInfo getReportInformation();

    void start();

    void cleanup();

    void postProcessing(ClientReport report);

    ClientProbeResult runProbe(IDispatcher probe, String hostnamePrefix, String uid, ClientReport report,
            Object additionalParameters)
            throws InterruptedException, ExecutionException;

    ExecutorService getSecondaryExecutor();
}