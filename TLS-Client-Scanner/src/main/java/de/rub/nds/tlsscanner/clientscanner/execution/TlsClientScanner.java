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
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.BasicProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DheParameterProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ForcedCompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Version13RandomProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsClientScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ClientScannerConfig config;
    private final List<ScannerProbe> probeList;
    private final List<AfterProbe> afterList;

    public TlsClientScanner(ClientScannerConfig config, Callable<Integer> clientAfterPreInitCallback) {

        this.config = config;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3);
        parallelExecutor.setDefaultBeforeTransportInitCallback(clientAfterPreInitCallback);
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    private void fillDefaultProbeLists() {
        probeList.add(new BasicProbe(parallelExecutor, config));
        probeList.add(new DheParameterProbe(parallelExecutor, config));
        probeList.add(new ForcedCompressionProbe(parallelExecutor, config));
        probeList.add(new FreakProbe(parallelExecutor, config));
        probeList.add(new Version13RandomProbe(parallelExecutor, config));
        probeList.add(new VersionProbe(parallelExecutor, config));
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
