/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.execution;

import de.rub.nds.scanner.core.execution.ScanJob;
import de.rub.nds.scanner.core.execution.ThreadedScanJobExecutor;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.BasicProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DheParameterProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ForcedCompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Version13RandomProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.execution.TlsScanner;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsClientScanner extends TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ParallelExecutor parallelExecutor;
    private final ClientScannerConfig config;

    public TlsClientScanner(ClientScannerConfig config, Callable<Integer> clientAfterPreInitCallback) {
        super(config.getProbes());
        this.config = config;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3);
        parallelExecutor.setDefaultBeforeTransportInitCallback(clientAfterPreInitCallback);
        fillDefaultProbeLists();
    }

    @Override
    protected void fillDefaultProbeLists() {
        addProbeToProbeList(new BasicProbe(parallelExecutor, config));
        addProbeToProbeList(new DheParameterProbe(parallelExecutor, config));
        addProbeToProbeList(new ForcedCompressionProbe(parallelExecutor, config));
        addProbeToProbeList(new FreakProbe(parallelExecutor, config));
        addProbeToProbeList(new Version13RandomProbe(parallelExecutor, config));
        addProbeToProbeList(new VersionProbe(parallelExecutor, config));
    }

    public ClientReport scan() {

        ThreadedScanJobExecutor executor = null;
        try {
            ScanJob job = new ScanJob(probeList, afterList);
            executor = new ThreadedScanJobExecutor(config, job, config.getParallelProbes(), "");
            ClientReport report = (ClientReport) executor.execute(new ClientReport());
            return report;
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
        }
    }

}
