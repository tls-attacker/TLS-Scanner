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
import java.util.concurrent.atomic.AtomicLong;
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
        // Temporary workaround: disable JAR URL connection caching globally to prevent
        // concurrent scans from closing a shared JarFile handle. GuidelineIO.listXmlFiles()
        // uses JarURLConnection.getJarFile() which returns a cached instance; closing one
        // scan's TlsServerScanner causes "zip file closed" errors in concurrent scans.
        // Tracked upstream: https://github.com/tls-attacker/TLS-Scanner-Development/issues/772
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

        ServerScannerConfig config = createServerScannerConfig(scanTarget);

        // Per-target write throttle: limit how often partial results are pushed to MongoDB.
        // State is local to this scan() invocation, so each scan target is throttled
        // independently and there is no shared state across concurrently scanned targets.
        long throttleMs = scanConfig.getPartialResultThrottleMs();
        AtomicLong lastPartialWrite = new AtomicLong(0L);

        ProbeProgressCallback progressCallback =
                (probe, reportInProgress, completed, total) ->
                        handleProgressUpdate(
                                probe,
                                reportInProgress,
                                completed,
                                total,
                                scanTarget,
                                jobDescription,
                                progressConsumer,
                                throttleMs,
                                lastPartialWrite);

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

    /** Builds the {@link ServerScannerConfig} for a scan target from the {@link TlsScanConfig}. */
    ServerScannerConfig createServerScannerConfig(ScanTarget scanTarget) {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ServerScannerConfig config = new ServerScannerConfig(generalDelegate);
        config.getExecutorConfig().setScanDetail(scanConfig.getScannerDetail());
        config.getExecutorConfig().setParallelProbes(scanConfig.getParallelProbes());
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
        return config;
    }

    private Document createDocumentFromSiteReport(ServerReport report) {
        if (report == null) {
            return null;
        }
        if (report.getServerIsAlive() != null && !report.getServerIsAlive()) {
            return null;
        }
        Document document = new Document();
        document.put("report", Document.parse(reportJsonMapper.toJsonString(report)));
        return document;
    }

    /**
     * Handles progress updates from the scanner by creating a partial result document and passing
     * it to the progress consumer.
     *
     * <p>Writes are throttled per scan target: at most one partial result is forwarded per {@code
     * throttleMs} window. Updates that fall inside an open window are skipped entirely, avoiding
     * both the MongoDB write and the (expensive) report serialization. The first update of a scan
     * always goes through, and the final complete result is written separately by the worker, so
     * the end-state is never lost.
     */
    @SuppressWarnings("rawtypes")
    private void handleProgressUpdate(
            ScannerProbe probe,
            ScanReport report,
            int completed,
            int total,
            ScanTarget scanTarget,
            ScanJobDescription jobDescription,
            Consumer<Document> progressConsumer,
            long throttleMs,
            AtomicLong lastPartialWrite) {
        if (!allowWrite(throttleMs, lastPartialWrite, System.currentTimeMillis())) {
            LOGGER.debug(
                    "Partial result throttled (within {}ms window): [{}/{}] {}",
                    throttleMs,
                    completed,
                    total,
                    probe.getType().getName());
            return;
        }
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

    /**
     * Leading-edge throttle gate. Returns {@code true} (and records {@code now} as the last write
     * time) when a write is allowed, i.e. either throttling is disabled ({@code throttleMs <= 0}),
     * this is the first write, or at least {@code throttleMs} has elapsed since the last write.
     * Thread-safe: when multiple probe callbacks fire concurrently for the same scan, only one wins
     * the window edge via {@link AtomicLong#compareAndSet}.
     */
    static boolean allowWrite(long throttleMs, AtomicLong lastPartialWrite, long now) {
        if (throttleMs <= 0) {
            return true;
        }
        long last = lastPartialWrite.get();
        if (last != 0L && now - last < throttleMs) {
            return false;
        }
        return lastPartialWrite.compareAndSet(last, now);
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
}
