/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.crawler.core.BulkScanWorker;
import de.rub.nds.crawler.data.ScanTarget;
import de.rub.nds.scanner.core.execution.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** TLS scan that uses the TLS-Scanner. */
public class TlsScanWorker extends BulkScanWorker<TlsScanConfig> {

    private static final Logger LOGGER = LogManager.getLogger();
    private ParallelExecutor parallelExecutor;
    private final int parallelConnectionThreads;

    public TlsScanWorker(
            String bulkScanID,
            int parallelConnectionThreads,
            TlsScanConfig scanConfig,
            int parallelScanThreads) {
        super(bulkScanID, scanConfig, parallelScanThreads);
        this.parallelConnectionThreads = parallelConnectionThreads;
    }

    @Override
    public synchronized void initInternal() {
        if (parallelExecutor != null) {
            throw new IllegalStateException("Parallel executor already initialized");
        }
        parallelExecutor =
                new ParallelExecutor(
                        parallelConnectionThreads,
                        scanConfig.getReexecutions(),
                        new NamedThreadFactory("TLS bulk scan worker " + bulkScanId));
    }

    @Override
    public synchronized void cleanupInternal() {
        if (parallelExecutor == null) {
            throw new IllegalStateException("Parallel executor not initialized");
        }
        parallelExecutor.shutdown();
        parallelExecutor = null;
    }

    @Override
    public Document scan(ScanTarget scanTarget) {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ServerScannerConfig config = new ServerScannerConfig(generalDelegate);
        config.getExecutorConfig().setScanDetail(scanConfig.getScannerDetail());
        config.setTimeout(scanConfig.getTimeout());
        config.getClientDelegate().setHost(scanTarget.getIp() + ":" + scanTarget.getPort());
        config.getClientDelegate().setSniHostname(scanTarget.getHostname());
        config.getStartTlsDelegate().setStarttlsType(scanConfig.getStarttlsType());

        ServerReport report;
        try (TlsServerScanner scanner = new TlsServerScanner(config, parallelExecutor)) {
            LOGGER.info("Started scanning '{}' ({})", scanTarget, scanConfig.getScannerDetail());
            report = scanner.scan();
        }
        LOGGER.info(
                "Finished scanning '{}' ({}) in {} s",
                scanTarget,
                scanConfig.getScannerDetail(),
                (report.getScanEndTime() - report.getScanStartTime()) / 1000);
        return createDocumentFromSiteReport(report);
    }

    private Document createDocumentFromSiteReport(ServerReport report) {
        if (report.getServerIsAlive() == null || report.getServerIsAlive()) {
            return null;
        }
        Document document = new Document();
        document.put("report", report);
        return document;
    }
}
