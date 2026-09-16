/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.crawler.data.BulkScan;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanResult;
import de.rub.nds.crawler.data.ScanTarget;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportJsonMapper;
import java.util.List;
import org.bson.Document;
import org.junit.jupiter.api.Test;

public class TlsScanWorkerTest {

    /** No-op persistence provider for testing */
    private static final IPersistenceProvider NO_OP_PERSISTENCE_PROVIDER =
            new IPersistenceProvider() {
                @Override
                public void insertScanResult(ScanResult scanResult, ScanJobDescription job) {}

                @Override
                public void insertBulkScan(BulkScan bulkScan) {}

                @Override
                public void updateBulkScan(BulkScan bulkScan) {}

                @Override
                public List<ScanResult> getScanResultsByTarget(
                        String dbName, String collectionName, String target) {
                    return List.of();
                }

                @Override
                public ScanResult getScanResultById(
                        String dbName, String collectionName, String id) {
                    return null;
                }

                @Override
                public ScanResult getScanResultByScanJobDescriptionId(
                        String dbName, String collectionName, String scanJobDescriptionId) {
                    return null;
                }

                @Override
                public void upsertPartialResult(ScanJobDescription job, ScanResult partialResult) {}
            };

    private static TlsScanWorker createWorker() {
        TlsScanConfig config =
                new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, 1, StarttlsType.NONE, List.of());
        return new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);
    }

    // ---- Init / cleanup tests ----

    @Test
    public void testCleanupWithoutInit() {
        TlsScanWorker worker = createWorker();
        assertThrows(IllegalStateException.class, worker::cleanupInternal);
    }

    @Test
    public void testInitAfterInit() {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        assertThrows(IllegalStateException.class, worker::initInternal);
        worker.cleanupInternal();
    }

    // ---- ServerScannerConfig parallelProbes propagation ----

    @Test
    public void testCreateServerScannerConfigPropagatesParallelProbes() {
        TlsScanConfig config =
                new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, 4, StarttlsType.NONE, List.of());
        TlsScanWorker worker =
                new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);

        assertEquals(
                4,
                worker.createServerScannerConfig(createScanTarget())
                        .getExecutorConfig()
                        .getParallelProbes());
    }

    @Test
    public void testCreateServerScannerConfigPropagatesZeroParallelProbes() {
        TlsScanConfig config =
                new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, 0, StarttlsType.NONE, List.of());
        TlsScanWorker worker =
                new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);

        assertEquals(
                0,
                worker.createServerScannerConfig(createScanTarget())
                        .getExecutorConfig()
                        .getParallelProbes());
    }

    /**
     * The stored report must keep Jackson's type id. Without it the report is not polymorphically
     * resolvable and consumers cannot deserialize it back into a {@link ServerReport}.
     */
    @Test
    public void storedReportKeepsJacksonTypeId() {
        ServerReport report = new ServerReport("example.test", 443);
        report.setServerIsAlive(true);

        Document document = createWorker().createDocumentFromSiteReport(report);

        assertNotNull(document, "Expected a document for a reachable target");
        Object storedReport = document.get("report");
        assertInstanceOf(
                Document.class, storedReport, "Expected the report to be stored as a document");
        assertEquals(
                "de.rub.nds.tlsscanner.serverscanner.report.ServerReport",
                ((Document) storedReport).get("@class"),
                "Stored report is missing its @class type id and cannot be deserialized back");

        ServerReport roundTripped =
                new ServerReportJsonMapper()
                        .objectMapper.convertValue(storedReport, ServerReport.class);
        assertNotNull(roundTripped, "Expected the stored report to round-trip back");
        assertEquals("example.test", roundTripped.getHost(), "Expected the host to survive");
    }

    private static ScanTarget createScanTarget() {
        ScanTarget scanTarget = new ScanTarget();
        scanTarget.setIp("127.0.0.1");
        scanTarget.setPort(443);
        scanTarget.setHostname("localhost");
        return scanTarget;
    }
}
