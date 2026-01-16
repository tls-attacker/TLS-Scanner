/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.crawler.constant.JobStatus;
import de.rub.nds.crawler.core.BulkScanWorker;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanTarget;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.execution.NamedThreadFactory;
import de.rub.nds.scanner.core.execution.ProbeProgressCallback;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportJsonMapper;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** TLS scan that uses the TLS-Scanner. */
public class TlsScanWorker extends BulkScanWorker<TlsScanConfig> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final long PARTIAL_RESULT_THROTTLE_MS = 5000; // 5 seconds

    /** Executor passed to TLS-Scanner. It is used to execute the States, i.e. the connections. */
    private ParallelExecutor parallelExecutor;

    private final int parallelConnectionThreads;

    private final ServerReportJsonMapper mapper;

    // Throttling for partial result updates
    private long lastPartialResultUpdate = 0;

    public TlsScanWorker(
            String bulkScanID,
            int parallelConnectionThreads,
            TlsScanConfig scanConfig,
            int parallelScanThreads,
            IPersistenceProvider persistenceProvider) {
        super(bulkScanID, scanConfig, parallelScanThreads, persistenceProvider);
        if (parallelConnectionThreads <= 0) {
            throw new IllegalArgumentException("parallelConnectionThreads must be positive");
        }
        this.parallelConnectionThreads = parallelConnectionThreads;
        this.mapper = new ServerReportJsonMapper();
    }

    @Override
    public synchronized void initInternal() {
        if (parallelExecutor != null) {
            throw new IllegalStateException("Parallel executor already initialized");
        }
        parallelExecutor =
                ParallelExecutor.create(
                        parallelConnectionThreads,
                        scanConfig.getReexecutions(),
                        new NamedThreadFactory(
                                "TLS connection executor (bulk scan " + bulkScanId + ")"));
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
    public Document scan(ScanJobDescription jobDescription, Consumer<Document> progressConsumer) {
        // Reset throttle state for this new scan
        lastPartialResultUpdate = 0;

        ScanTarget scanTarget = jobDescription.getScanTarget();

        // Ensure parallelExecutor is initialized before use
        synchronized (this) {
            if (parallelExecutor == null) {
                throw new IllegalStateException(
                        "Parallel executor not initialized. Call init() first.");
            }
        }

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ServerScannerConfig config = new ServerScannerConfig(generalDelegate);
        config.getExecutorConfig().setScanDetail(scanConfig.getScannerDetail());
        config.setTimeout(scanConfig.getTimeout());
        config.getClientDelegate().setHost(scanTarget.getIp() + ":" + scanTarget.getPort());
        config.getClientDelegate().setSniHostname(scanTarget.getHostname());
        config.getStartTlsDelegate().setStarttlsType(scanConfig.getStarttlsType());

        // Set excluded probes if configured
        if (scanConfig.getExcludedProbes() != null && !scanConfig.getExcludedProbes().isEmpty()) {
            config.getExecutorConfig().setExcludedProbes(scanConfig.getExcludedProbes());
            LOGGER.info(
                    "Excluding {} probes from scan: {}",
                    scanConfig.getExcludedProbes().size(),
                    scanConfig.getExcludedProbes().stream().map(p -> p.getName()).toList());
        }

        // Create progress callback to notify the consumer with partial results
        ProbeProgressCallback progressCallback =
                (probe, report, completed, total) -> {
                    // Throttle updates (max once per 5 seconds)
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastPartialResultUpdate < PARTIAL_RESULT_THROTTLE_MS) {
                        return; // Skip this update, too soon since last one
                    }

                    try {
                        // Cast ScanReport to ServerReport (it's a ServerReport at runtime)
                        ServerReport serverReport = (ServerReport) report;
                        String partialReportJson = mapper.toJsonString(serverReport);

                        // Create nested result document (matches ScanResult.result field)
                        Document resultDoc = new Document();
                        resultDoc.put("report", partialReportJson);
                        // Add progress metadata in result document
                        resultDoc.put("isPartial", true);
                        resultDoc.put("completedProbes", completed);
                        resultDoc.put("totalProbes", total);
                        resultDoc.put("lastProbeName", probe.getType().getName());
                        resultDoc.put("percentage", (completed * 100.0) / total);
                        resultDoc.put("lastUpdateTime", currentTime);

                        // Create scanTarget document
                        Document scanTargetDoc = new Document();
                        scanTargetDoc.put("ip", scanTarget.getIp());
                        scanTargetDoc.put("port", scanTarget.getPort());
                        scanTargetDoc.put("hostname", scanTarget.getHostname());

                        // Create main document matching ScanResult structure
                        Document partialResultDoc = new Document();
                        partialResultDoc.put("_id", jobDescription.getId().toString());
                        partialResultDoc.put(
                                "scanJobDescription",
                                jobDescription.getId().toString()); // Required for webapp query
                        partialResultDoc.put("bulkScan", bulkScanId);
                        partialResultDoc.put("scanTarget", scanTargetDoc);
                        partialResultDoc.put(
                                "resultStatus", JobStatus.RUNNING.name()); // Use RUNNING status
                        partialResultDoc.put("result", resultDoc);

                        // Notify progress consumer (handles both future update and persistence)
                        progressConsumer.accept(partialResultDoc);

                        lastPartialResultUpdate = currentTime;

                        LOGGER.debug(
                                "Progress update: [{}/{}] {:.1f}% - {}",
                                completed,
                                total,
                                (completed * 100.0) / total,
                                probe.getType().getName());
                    } catch (Exception e) {
                        LOGGER.warn("Failed to process partial result", e);
                    }
                };

        ServerReport report;
        try (TlsServerScanner scanner = new TlsServerScanner(config, parallelExecutor)) {
            // Set progress callback before scanning
            scanner.setProgressCallback(progressCallback);

            LOGGER.info("Started scanning '{}' ({})", scanTarget, scanConfig.getScannerDetail());
            report = scanner.scan();
        }

        // The final result (written by Worker/MongoPersistenceProvider) will overwrite
        // the partial result using the same _id (job UUID).

        long scanDurationSeconds = (report.getScanEndTime() - report.getScanStartTime()) / 1000;
        LOGGER.info(
                "Finished scanning '{}' ({}) in {} s (server alive: {})",
                scanTarget,
                scanConfig.getScannerDetail(),
                scanDurationSeconds,
                report.getServerIsAlive());
        return createDocumentFromSiteReport(report);
    }

    private Document createDocumentFromSiteReport(ServerReport report) {
        if (report == null) {
            return null;
        }
        if (report.getServerIsAlive() != null && !report.getServerIsAlive()) {
            return null;
        }
        Document document = new Document();
        // Serialize the report to JSON string (matching partial results format)
        try {
            String reportJson = mapper.toJsonString(report);
            document.put("report", reportJson);
        } catch (Exception e) {
            LOGGER.error("Failed to serialize ServerReport to JSON", e);
            throw new RuntimeException("Failed to serialize ServerReport to JSON", e);
        }
        return document;
    }
}
