/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.crawler.data.BulkScan;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanResult;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
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
                public void upsertPartialResult(ScanJobDescription job, Document partialResult) {}
            };

    @Test
    public void testCleanupWithoutInit() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        TlsScanWorker worker =
                new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);

        // Should throw IllegalStateException since parallelExecutor is null
        assertThrows(IllegalStateException.class, worker::cleanupInternal);
    }

    @Test
    public void testInitAfterInit() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        TlsScanWorker worker =
                new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);

        // Initialize once
        worker.initInternal();

        // Second init should throw IllegalStateException
        assertThrows(IllegalStateException.class, worker::initInternal);

        // Clean up
        worker.cleanupInternal();
    }
}
