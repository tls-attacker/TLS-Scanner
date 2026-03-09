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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** TLS scan that uses the TLS-Scanner. */
public class TlsScanWorker extends BulkScanWorker<TlsScanConfig> {

    private static final Logger LOGGER = LogManager.getLogger();
    static final long PARTIAL_RESULT_THROTTLE_MS = 5000; // 5 seconds

    /** Executor passed to TLS-Scanner. It is used to execute the States, i.e. the connections. */
    private ParallelExecutor parallelExecutor;

    private final int parallelConnectionThreads;

    // JSON mapper for serializing ServerReport to JSON strings for MongoDB storage
    private final ServerReportJsonMapper reportJsonMapper = new ServerReportJsonMapper();

    // Throttling for partial result updates
    private long lastPartialResultUpdate = 0;
    private ScheduledExecutorService throttleScheduler;
    private ScheduledFuture<?> pendingPublishTask;
    private Document pendingPartialResult;
    private Consumer<Document> pendingProgressConsumer;

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
        parallelExecutor =
                ParallelExecutor.create(
                        parallelConnectionThreads,
                        scanConfig.getReexecutions(),
                        new NamedThreadFactory(
                                "TLS connection executor (bulk scan " + bulkScanId + ")"));
        // Initialize throttle scheduler for delayed partial result publishing
        throttleScheduler =
                new ScheduledThreadPoolExecutor(
                        1,
                        new NamedThreadFactory(
                                "partial-result-throttle (bulk scan " + bulkScanId + ")"));
    }

    @Override
    public synchronized void cleanupInternal() {
        if (parallelExecutor == null) {
            throw new IllegalStateException("Parallel executor not initialized");
        }
        parallelExecutor.shutdown();
        parallelExecutor = null;
        // Shutdown throttle scheduler
        if (throttleScheduler != null) {
            throttleScheduler.shutdownNow();
            throttleScheduler = null;
        }
        pendingPartialResult = null;
        pendingProgressConsumer = null;
        pendingPublishTask = null;
    }

    @Override
    public Document scan(ScanJobDescription jobDescription, Consumer<Document> progressConsumer) {
        resetThrottleState();

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
                (probe, report, completed, total) ->
                        handleProgressUpdate(
                                probe,
                                report,
                                completed,
                                total,
                                scanTarget,
                                jobDescription,
                                progressConsumer);

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
        document.put("report", report);
        return document;
    }

    /** Resets throttle state between scans. Package-private for testing. */
    void resetThrottleState() {
        lastPartialResultUpdate = 0;
        pendingPartialResult = null;
        pendingProgressConsumer = null;
        if (pendingPublishTask != null) {
            pendingPublishTask.cancel(false);
            pendingPublishTask = null;
        }
    }

    /**
     * Handles progress updates from the scanner by creating a partial result document and notifying
     * the progress consumer. Updates are throttled to avoid excessive overhead.
     *
     * <p>Throttling behavior: When an update arrives during the throttle period, it is saved as
     * pending and scheduled to be published after the throttle period ends. If another update
     * arrives before the scheduled publish, it replaces the pending update, ensuring the latest
     * state is always published.
     *
     * @param probe The probe that just completed
     * @param report The current scan report (partial)
     * @param completed Number of completed probes
     * @param total Total number of probes
     * @param scanTarget The target being scanned
     * @param jobDescription The job description for this scan
     * @param progressConsumer Consumer to notify with the partial result
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
        long currentTime = System.currentTimeMillis();

        try {
            Document partialResultDoc =
                    buildPartialResultDocument(
                            (ServerReport) report,
                            completed,
                            total,
                            probe,
                            scanTarget,
                            jobDescription,
                            currentTime);

            submitThrottledUpdate(partialResultDoc, progressConsumer, currentTime);
        } catch (Exception e) {
            LOGGER.warn("Failed to process partial result", e);
        }
    }

    /**
     * Submits a partial result through the throttle mechanism. If enough time has elapsed since the
     * last update, publishes immediately. Otherwise, saves as pending and schedules publication
     * after the throttle period.
     *
     * <p>Package-private for testing.
     */
    void submitThrottledUpdate(
            Document partialResultDoc, Consumer<Document> progressConsumer, long currentTime) {
        synchronized (this) {
            if (currentTime - lastPartialResultUpdate >= PARTIAL_RESULT_THROTTLE_MS) {
                // Can publish immediately
                publishPartialResult(partialResultDoc, progressConsumer, currentTime);
            } else {
                // Throttled - save as pending and schedule publish after throttle period
                pendingPartialResult = partialResultDoc;
                pendingProgressConsumer = progressConsumer;

                // Cancel any existing scheduled task (we have a newer update)
                if (pendingPublishTask != null && !pendingPublishTask.isDone()) {
                    pendingPublishTask.cancel(false);
                }

                // Schedule publish after remaining throttle time
                long delay = PARTIAL_RESULT_THROTTLE_MS - (currentTime - lastPartialResultUpdate);
                pendingPublishTask =
                        throttleScheduler.schedule(
                                this::publishPendingUpdate, delay, TimeUnit.MILLISECONDS);

                Document resultDoc = (Document) partialResultDoc.get("result");
                LOGGER.debug(
                        "Progress update throttled, scheduled for {}ms: [{}/{}] {:.1f}% - {}",
                        delay,
                        resultDoc.get("completedProbes"),
                        resultDoc.get("totalProbes"),
                        resultDoc.get("percentage"),
                        resultDoc.get("lastProbeName"));
            }
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
        // Serialize ServerReport to JSON string so it can be stored via raw MongoCollection
        // (which uses BSON codecs, not Jackson) and read back via getString("report")
        String reportJson = reportJsonMapper.toJsonString(serverReport);

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

    /** Publishes a partial result immediately and updates throttle state. */
    private void publishPartialResult(
            Document partialResultDoc, Consumer<Document> progressConsumer, long currentTime) {
        progressConsumer.accept(partialResultDoc);
        lastPartialResultUpdate = currentTime;
        pendingPartialResult = null;
        pendingProgressConsumer = null;

        Document resultDoc = (Document) partialResultDoc.get("result");
        LOGGER.debug(
                "Progress update: [{}/{}] {:.1f}% - {}",
                resultDoc.get("completedProbes"),
                resultDoc.get("totalProbes"),
                resultDoc.get("percentage"),
                resultDoc.get("lastProbeName"));
    }

    /** Called by scheduler to publish the pending partial result after throttle period. */
    private synchronized void publishPendingUpdate() {
        if (pendingPartialResult != null && pendingProgressConsumer != null) {
            publishPartialResult(
                    pendingPartialResult, pendingProgressConsumer, System.currentTimeMillis());
        }
    }
}
