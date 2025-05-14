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

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import org.junit.jupiter.api.Test;

public class TlsScanWorkerTest {

    @Test
    public void testCleanupWithoutInit() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        TlsScanWorker worker = new TlsScanWorker("test-scan", 2, config, 3);

        // Should throw IllegalStateException since parallelExecutor is null
        assertThrows(IllegalStateException.class, worker::cleanupInternal);
    }

    @Test
    public void testInitAfterInit() {
        TlsScanConfig config = new TlsScanConfig(ScannerDetail.NORMAL, 1, 2000, StarttlsType.NONE);
        TlsScanWorker worker = new TlsScanWorker("test-scan", 2, config, 3);

        // Initialize once
        worker.initInternal();

        // Second init should throw IllegalStateException
        assertThrows(IllegalStateException.class, worker::initInternal);

        // Clean up
        worker.cleanupInternal();
    }
}
