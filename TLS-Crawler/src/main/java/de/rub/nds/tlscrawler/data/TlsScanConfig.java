/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.crawler.core.BulkScanWorker;
import de.rub.nds.crawler.data.ScanConfig;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.core.TlsScanWorker;

public class TlsScanConfig extends ScanConfig {
    private StarttlsType starttlsType;

    public TlsScanConfig(
            ScannerDetail scannerDetail, int reexecutions, int timeout, StarttlsType starttlsType) {
        super(scannerDetail, reexecutions, timeout);
        this.starttlsType = starttlsType;
    }

    @Override
    public BulkScanWorker<TlsScanConfig> createWorker(
            String bulkScanID, int parallelConnectionThreads, int parallelScanThreads) {
        return new TlsScanWorker(bulkScanID, parallelConnectionThreads, this, parallelScanThreads);
    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }
}
