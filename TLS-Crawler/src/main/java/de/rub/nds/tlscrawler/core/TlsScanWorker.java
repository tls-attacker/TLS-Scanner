/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.ReplaceOptions;
import de.rub.nds.crawler.constant.JobStatus;
import de.rub.nds.crawler.core.BulkScanWorker;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanTarget;
import de.rub.nds.scanner.core.execution.NamedThreadFactory;
import de.rub.nds.scanner.core.execution.ProbeProgressCallback;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportJsonMapper;
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

    // MongoDB client for persisting partial results
    private MongoClient mongoClient;
    private MongoDatabase mongoDatabase;
    private MongoCollection<Document> partialResultsCollection;

    // Throttling for partial result writes
    private long lastPartialResultWrite = 0;

    public TlsScanWorker(
            String bulkScanID,
            int parallelConnectionThreads,
            TlsScanConfig scanConfig,
            int parallelScanThreads) {
        super(bulkScanID, scanConfig, parallelScanThreads);
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

        // Initialize MongoDB client for partial results persistence
        try {
            String mongoHost = System.getenv().getOrDefault("MONGODB_HOST", "mongodb");
            int mongoPort = Integer.parseInt(System.getenv().getOrDefault("MONGODB_PORT", "27017"));
            String mongoUser = System.getenv().getOrDefault("MONGODB_USER", "mongoadmin");
            String mongoPassword = System.getenv().getOrDefault("MONGODB_PASSWORD", "mongoadminpw");
            String mongoAuthSource = System.getenv().getOrDefault("MONGODB_AUTHSOURCE", "admin");
            String mongoDbName = System.getenv().getOrDefault("MONGODB_DATABASE", "tlsscanner");
            String mongoCollection = System.getenv().getOrDefault("MONGODB_COLLECTION", "scans");

            ConnectionString connectionString =
                    new ConnectionString("mongodb://" + mongoHost + ":" + mongoPort);
            MongoCredential credentials =
                    MongoCredential.createCredential(
                            mongoUser, mongoAuthSource, mongoPassword.toCharArray());

            MongoClientSettings settings =
                    MongoClientSettings.builder()
                            .credential(credentials)
                            .applyConnectionString(connectionString)
                            .build();

            mongoClient = MongoClients.create(settings);
            // Use environment variables for database and collection to match WebApp expectations
            mongoDatabase = mongoClient.getDatabase(mongoDbName);
            partialResultsCollection = mongoDatabase.getCollection(mongoCollection);

            LOGGER.info(
                    "MongoDB client initialized for partial results persistence at {}:{}",
                    mongoHost,
                    mongoPort);
        } catch (Exception e) {
            LOGGER.warn(
                    "Failed to initialize MongoDB client for partial results, will skip partial persistence",
                    e);
            mongoClient = null;
        }
    }

    @Override
    public synchronized void cleanupInternal() {
        if (parallelExecutor == null) {
            throw new IllegalStateException("Parallel executor not initialized");
        }
        parallelExecutor.shutdown();
        parallelExecutor = null;

        // Close MongoDB connection
        if (mongoClient != null) {
            try {
                mongoClient.close();
                LOGGER.info("MongoDB client closed");
            } catch (Exception e) {
                LOGGER.warn("Error closing MongoDB client", e);
            }
            mongoClient = null;
            mongoDatabase = null;
            partialResultsCollection = null;
        }
    }

    @Override
    public Document scan(ScanTarget scanTarget) {
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

        // Get the current job description to access the UUID
        ScanJobDescription jobDescription = getCurrentJobDescription();

        // Create progress callback to persist partial results to MongoDB
        ProbeProgressCallback progressCallback =
                (probe, report, completed, total) -> {
                    // Throttle writes to MongoDB (max once per 5 seconds)
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastPartialResultWrite < PARTIAL_RESULT_THROTTLE_MS) {
                        return; // Skip this update, too soon since last write
                    }

                    if (mongoClient != null
                            && partialResultsCollection != null
                            && jobDescription != null) {
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
                            // Use UUID as document ID (same as final result will use)
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

                            // Upsert: replace if exists, insert if not
                            partialResultsCollection.replaceOne(
                                    new Document("_id", jobDescription.getId().toString()),
                                    partialResultDoc,
                                    new ReplaceOptions().upsert(true));

                            lastPartialResultWrite = currentTime;

                            LOGGER.debug(
                                    "Persisted partial result to MongoDB: [{}/{}] {:.1f}% - {}",
                                    completed,
                                    total,
                                    (completed * 100.0) / total,
                                    probe.getType().getName());
                        } catch (Exception e) {
                            LOGGER.warn("Failed to persist partial result to MongoDB", e);
                        }
                    }
                };

        ServerReport report;
        try (TlsServerScanner scanner = new TlsServerScanner(config, parallelExecutor)) {
            // Set progress callback before scanning
            scanner.setProgressCallback(progressCallback);

            LOGGER.info("Started scanning '{}' ({})", scanTarget, scanConfig.getScannerDetail());
            report = scanner.scan();
        }

        // After scan completes, delete the partial result document
        // The Worker will create the final result with the UUID as _id
        if (mongoClient != null && partialResultsCollection != null && jobDescription != null) {
            try {
                partialResultsCollection.deleteOne(
                        new Document("_id", jobDescription.getId().toString()));
                LOGGER.info(
                        "Deleted partial result document for {}, final result will be created by Worker with UUID",
                        scanTarget);
            } catch (Exception e) {
                LOGGER.warn("Failed to delete partial result from MongoDB", e);
            }
        }

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
            // Fallback: put the object directly (may not work as expected)
            document.put("report", report);
        }
        return document;
    }
}
