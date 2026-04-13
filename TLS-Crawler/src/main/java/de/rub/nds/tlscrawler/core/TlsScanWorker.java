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
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportJsonMapper;
import java.net.URLConnection;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** TLS scan that uses the TLS-Scanner. */
public class TlsScanWorker extends BulkScanWorker<TlsScanConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Executor passed to TLS-Scanner. It is used to execute the States, i.e. the connections. */
    private ParallelExecutor parallelExecutor;

    private final int parallelConnectionThreads;

    // JSON mapper for serializing ServerReport to JSON strings for MongoDB storage.
    // BigInteger values are serialized as strings to avoid BSON JSON parser overflow
    // on cryptographic values (RSA moduli, DH parameters).
    private final ServerReportJsonMapper reportJsonMapper;

    {
        reportJsonMapper = new ServerReportJsonMapper();
        reportJsonMapper
                .objectMapper
                .configOverride(java.math.BigInteger.class)
                .setFormat(
                        com.fasterxml.jackson.annotation.JsonFormat.Value.forShape(
                                com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING));
    }

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
    }

    @Override
    public synchronized void initInternal() {
        if (parallelExecutor != null) {
            throw new IllegalStateException("Parallel executor already initialized");
        }
        // Disable default URL connection caching to prevent concurrent scans from
        // closing a shared JarFile handle (GuidelineIO.listXmlFiles uses
        // JarURLConnection.getJarFile() which returns the cached instance).
        // Without this, closing one scan's TlsServerScanner can cause
        // "zip file closed" errors in concurrent scans reading guideline XML files.
        URLConnection.setDefaultUseCaches("jar", false);
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
        if (scanConfig.getExcludedProbes() != null && !scanConfig.getExcludedProbes().isEmpty()) {
            config.getExecutorConfig().setExcludedProbes(scanConfig.getExcludedProbes());
            LOGGER.info(
                    "Excluding {} probes from scan: {}",
                    scanConfig.getExcludedProbes().size(),
                    scanConfig.getExcludedProbes().stream().map(p -> p.getName()).toList());
        }

        ProbeProgressCallback progressCallback =
                (probe, reportInProgress, completed, total) ->
                        handleProgressUpdate(
                                probe,
                                reportInProgress,
                                completed,
                                total,
                                scanTarget,
                                jobDescription,
                                progressConsumer);

        ServerReport report;
        try (TlsServerScanner scanner =
                new TlsServerScanner(config, parallelExecutor, progressCallback)) {
            LOGGER.info("Started scanning '{}' ({})", scanTarget, scanConfig.getScannerDetail());
            report = scanner.scan();
        }

        // The final result (written by Worker/MongoPersistenceProvider) will overwrite
        // the partial result using the same _id (job UUID).

        if (report.getScanEndTime() != null && report.getScanStartTime() != null) {
            long scanDurationSeconds = (report.getScanEndTime() - report.getScanStartTime()) / 1000;
            LOGGER.info(
                    "Finished scanning '{}' ({}) in {} s (server alive: {})",
                    scanTarget,
                    scanConfig.getScannerDetail(),
                    scanDurationSeconds,
                    report.getServerIsAlive());
        } else {
            LOGGER.info(
                    "Finished scanning '{}' ({}) (server alive: {})",
                    scanTarget,
                    scanConfig.getScannerDetail(),
                    report.getServerIsAlive());
        }
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
        document.put("report", report);
        return document;
    }

    /**
     * Handles progress updates from the scanner by creating a partial result document and passing
     * it to the progress consumer. Throttling is handled transparently by BulkScanWorker.
     */
    @SuppressWarnings("rawtypes")
    private void handleProgressUpdate(
            ScannerProbe probe,
            ScanReport report,
            int completed,
            int total,
            ScanTarget scanTarget,
            ScanJobDescription jobDescription,
            Consumer<Document> progressConsumer) {
        try {
            Document partialResultDoc =
                    buildPartialResultDocument(
                            (ServerReport) report,
                            completed,
                            total,
                            probe,
                            scanTarget,
                            jobDescription,
                            System.currentTimeMillis());

            LOGGER.debug(
                    "Progress update: [{}/{}] {}% - {}",
                    completed,
                    total,
                    String.format("%.1f", (completed * 100.0) / total),
                    probe.getType().getName());

            progressConsumer.accept(partialResultDoc);
        } catch (Exception e) {
            LOGGER.warn("Failed to process partial result", e);
        }
    }

    /** Builds a partial result document from the current scan state. */
    @SuppressWarnings("rawtypes")
    private Document buildPartialResultDocument(
            ServerReport serverReport,
            int completed,
            int total,
            ScannerProbe probe,
            ScanTarget scanTarget,
            ScanJobDescription jobDescription,
            long currentTime) {
        // Serialize ServerReport to JSON string first (preserves polymorphic type info),
        // then parse into a BSON Document. BigIntegers are serialized as strings by the
        // mapper to avoid BSON JSON parser overflow on cryptographic values.
        String reportJson;
        try {
            reportJson = reportJsonMapper.objectMapper.writeValueAsString(serverReport);
        } catch (Exception e) {
            LOGGER.warn("Failed to serialize ServerReport to JSON", e);
            return null;
        }

        // Create nested result document (matches ScanResult.result field)
        Document resultDoc = new Document();
        resultDoc.put("report", Document.parse(reportJson));
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
        partialResultDoc.put("scanJobDescription", jobDescription.getId().toString());
        partialResultDoc.put("bulkScan", bulkScanId);
        partialResultDoc.put("scanTarget", scanTargetDoc);
        partialResultDoc.put("resultStatus", JobStatus.RUNNING.name());
        partialResultDoc.put("result", resultDoc);

        return partialResultDoc;
    }
}
