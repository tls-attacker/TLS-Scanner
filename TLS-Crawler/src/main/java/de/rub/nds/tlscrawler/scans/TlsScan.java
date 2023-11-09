/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.crawler.data.ScanJob;
import de.rub.nds.crawler.orchestration.IOrchestrationProvider;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.crawler.scans.Scan;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** TLS scan that uses the TLS-Scanner. */
public class TlsScan extends Scan {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ParallelExecutor parallelExecutor;

    public TlsScan(
            ScanJob scanJob,
            IOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            int parallelExecutorThreads) {
        super(scanJob, orchestrationProvider, persistenceProvider);
        // TODO share this parallel executor between scanners
        this.parallelExecutor =
                new ParallelExecutor(
                        parallelExecutorThreads, scanJob.getScanConfig().getReexecutions());
    }

    @Override
    public Document executeScan() {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ServerScannerConfig config = new ServerScannerConfig(generalDelegate);
        config.getExecutorConfig().setScanDetail(scanJob.getScanConfig().getScannerDetail());
        config.setTimeout(scanJob.getScanConfig().getTimeout());
        config.getClientDelegate()
                .setHost(scanJob.getScanTarget().getIp() + ":" + scanJob.getScanTarget().getPort());
        config.getClientDelegate().setSniHostname(scanJob.getScanTarget().getHostname());
        config.getStartTlsDelegate()
                .setStarttlsType(((TlsScanConfig) scanJob.getScanConfig()).getStarttlsType());

        TlsServerScanner scanner = new TlsServerScanner(config, parallelExecutor);

        LOGGER.info(
                "Started scanning '{}' ({})",
                scanJob.getScanTarget(),
                scanJob.getScanConfig().getScannerDetail());
        ServerReport report = scanner.scan();
        LOGGER.info(
                "Finished scanning '{}' ({}) in {} s",
                scanJob.getScanTarget(),
                scanJob.getScanConfig().getScannerDetail(),
                (report.getScanEndTime() - report.getScanStartTime()) / 1000);
        if (report.getServerIsAlive() == null || report.getServerIsAlive()) {
            return this.createDocumentFromSiteReport(report);
        } else {
            return null;
        }
    }

    @Override
    protected void onCleanup(boolean cancelled) {
        this.parallelExecutor.shutdown();
    }

    private Document createDocumentFromSiteReport(ServerReport report) {
        Document document = new Document();
        document.put("report", report);
        return document;
    }
}
