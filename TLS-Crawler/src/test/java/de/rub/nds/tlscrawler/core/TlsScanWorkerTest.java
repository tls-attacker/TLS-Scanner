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

import de.rub.nds.crawler.data.BulkScan;
import de.rub.nds.crawler.data.ScanJobDescription;
import de.rub.nds.crawler.data.ScanResult;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReportJsonMapper;
import java.lang.reflect.Field;
import java.math.BigInteger;
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

    // ---- BigInteger serialization test ----

    @Test
    public void testWorkerMapperSerializesBigIntegerAsString() throws Exception {
        TlsScanWorker worker = createWorker();
        Field mapperField = TlsScanWorker.class.getDeclaredField("reportJsonMapper");
        mapperField.setAccessible(true);
        ServerReportJsonMapper mapper = (ServerReportJsonMapper) mapperField.get(worker);

        // Value observed in worker logs while scanning clienttest.ssllabs.com.
        BigInteger observedLargeValue =
                new BigInteger(
                        "23235777100339028574507373434737534188189874546573570036432855192765758503092839408957293810586392913395074915145388372631304509545500894205268368620243109886042646318342985032645427643221078914059961844626779845609240043230483960366203172941012033305287554568893003977421555284966569748066789990300437606269755615491939546831313531005766049307389996721809826202757265051298762923396623698974332631879654648687074788108819545935552538608212055960243589404409801008498939970653159130011011073853021358993499694192070137832671174622203054365737383150429680560081388147116798168776777134124082922813987221115677142448433");

        String json = mapper.objectMapper.valueToTree(observedLargeValue).toString();
        assertEquals('"' + observedLargeValue.toString() + '"', json);
    }
}
