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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.crawler.data.BulkScan;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanResult;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
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

    private static TlsScanWorker createWorker() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        return new TlsScanWorker("test-scan", 2, config, 3, NO_OP_PERSISTENCE_PROVIDER);
    }

    /** Creates a minimal Document with the structure expected by submitThrottledUpdate. */
    private static Document createTestDocument(String probeName) {
        Document resultDoc = new Document();
        resultDoc.put("completedProbes", 1);
        resultDoc.put("totalProbes", 10);
        resultDoc.put("percentage", 10.0);
        resultDoc.put("lastProbeName", probeName);

        Document doc = new Document();
        doc.put("result", resultDoc);
        return doc;
    }

    private static String getLastProbeName(Document doc) {
        return ((Document) doc.get("result")).getString("lastProbeName");
    }

    // ---- Init / cleanup tests ----

    @Test
    public void testCleanupWithoutInit() {
        TlsScanWorker worker = createWorker();

        // Should throw IllegalStateException since parallelExecutor is null
        assertThrows(IllegalStateException.class, worker::cleanupInternal);
    }

    @Test
    public void testInitAfterInit() {
        TlsScanWorker worker = createWorker();

        // Initialize once
        worker.initInternal();

        // Second init should throw IllegalStateException
        assertThrows(IllegalStateException.class, worker::initInternal);

        // Clean up
        worker.cleanupInternal();
    }

    // ---- Throttle tests ----

    @Test
    public void testFirstUpdatePublishesImmediately() {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            List<Document> received = new ArrayList<>();
            // lastPartialResultUpdate starts at 0, so currentTime must be >= throttle window
            worker.submitThrottledUpdate(
                    createTestDocument("probe-1"),
                    received::add,
                    TlsScanWorker.DEFAULT_PARTIAL_RESULT_THROTTLE_MS);

            assertEquals(1, received.size());
            assertEquals("probe-1", getLastProbeName(received.get(0)));
        } finally {
            worker.cleanupInternal();
        }
    }

    @Test
    public void testUpdateWithinThrottleWindowIsDeferred() {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            List<Document> received = new ArrayList<>();
            long baseTime = 10000L;

            // First update - publishes immediately
            worker.submitThrottledUpdate(createTestDocument("probe-1"), received::add, baseTime);
            assertEquals(1, received.size());

            // Second update within throttle window - should NOT publish immediately
            worker.submitThrottledUpdate(
                    createTestDocument("probe-2"), received::add, baseTime + 1000);
            assertEquals(1, received.size());
        } finally {
            worker.cleanupInternal();
        }
    }

    @Test
    public void testUpdateAfterThrottleWindowPublishesImmediately() {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            List<Document> received = new ArrayList<>();
            long baseTime = 10000L;

            // First update - publishes immediately
            worker.submitThrottledUpdate(createTestDocument("probe-1"), received::add, baseTime);
            assertEquals(1, received.size());

            // Update after throttle window - should publish immediately
            long afterThrottle = baseTime + TlsScanWorker.DEFAULT_PARTIAL_RESULT_THROTTLE_MS;
            worker.submitThrottledUpdate(
                    createTestDocument("probe-2"), received::add, afterThrottle);
            assertEquals(2, received.size());
            assertEquals("probe-2", getLastProbeName(received.get(1)));
        } finally {
            worker.cleanupInternal();
        }
    }

    @Test
    public void testScheduledPublishFiresAfterDelay() throws Exception {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            CountDownLatch latch = new CountDownLatch(1);
            List<Document> received = Collections.synchronizedList(new ArrayList<>());
            long baseTime = 10000L;

            // First update - publishes immediately
            worker.submitThrottledUpdate(createTestDocument("probe-1"), received::add, baseTime);
            assertEquals(1, received.size());

            // Second update near end of throttle window → scheduled delay = 1ms
            Consumer<Document> latchConsumer =
                    doc -> {
                        received.add(doc);
                        latch.countDown();
                    };
            long nearEndOfWindow = baseTime + TlsScanWorker.DEFAULT_PARTIAL_RESULT_THROTTLE_MS - 1;
            worker.submitThrottledUpdate(
                    createTestDocument("probe-2"), latchConsumer, nearEndOfWindow);
            assertEquals(1, received.size()); // not published yet

            // Wait for the scheduled publish (1ms delay + generous margin)
            assertTrue(latch.await(2, TimeUnit.SECONDS));
            assertEquals(2, received.size());
            assertEquals("probe-2", getLastProbeName(received.get(1)));
        } finally {
            worker.cleanupInternal();
        }
    }

    @Test
    public void testNewerPendingUpdateReplacesPrevious() throws Exception {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            CountDownLatch latch = new CountDownLatch(1);
            List<Document> received = Collections.synchronizedList(new ArrayList<>());
            long baseTime = 10000L;

            // First update - publishes immediately
            worker.submitThrottledUpdate(createTestDocument("probe-1"), received::add, baseTime);
            assertEquals(1, received.size());

            Consumer<Document> latchConsumer =
                    doc -> {
                        received.add(doc);
                        latch.countDown();
                    };

            // Second update within window (delay = 3000ms)
            worker.submitThrottledUpdate(
                    createTestDocument("probe-2"), latchConsumer, baseTime + 2000);

            // Third update replaces second, near end of window (delay = 1ms)
            long nearEnd = baseTime + TlsScanWorker.DEFAULT_PARTIAL_RESULT_THROTTLE_MS - 1;
            worker.submitThrottledUpdate(createTestDocument("probe-3"), latchConsumer, nearEnd);

            // Wait for the scheduled publish
            assertTrue(latch.await(2, TimeUnit.SECONDS));

            // Only probe-1 (immediate) and probe-3 (latest pending) should be published
            assertEquals(2, received.size());
            assertEquals("probe-1", getLastProbeName(received.get(0)));
            assertEquals("probe-3", getLastProbeName(received.get(1)));
        } finally {
            worker.cleanupInternal();
        }
    }

    @Test
    public void testResetAllowsImmediatePublishAgain() {
        TlsScanWorker worker = createWorker();
        worker.initInternal();
        try {
            List<Document> received = new ArrayList<>();
            long baseTime = 10000L;

            // First update - publishes immediately
            worker.submitThrottledUpdate(createTestDocument("probe-1"), received::add, baseTime);
            assertEquals(1, received.size());

            // Within throttle window - deferred
            worker.submitThrottledUpdate(
                    createTestDocument("probe-2"), received::add, baseTime + 100);
            assertEquals(1, received.size());

            // Reset throttle state (cancels pending task, resets timestamp)
            worker.resetThrottleState();

            // After reset, next update should publish immediately regardless of timestamp
            worker.submitThrottledUpdate(
                    createTestDocument("probe-3"), received::add, baseTime + 200);
            assertEquals(2, received.size());
            assertEquals("probe-3", getLastProbeName(received.get(1)));
        } finally {
            worker.cleanupInternal();
        }
    }
}
