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
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.core.TlsScanWorker;
import java.util.List;

public class TlsScanConfig extends ScanConfig {
    private StarttlsType starttlsType;

    public TlsScanConfig(
            ScannerDetail scannerDetail, int reexecutions, int timeout, StarttlsType starttlsType) {
        this(scannerDetail, reexecutions, timeout, starttlsType, null);
    }

    public TlsScanConfig(
            ScannerDetail scannerDetail,
            int reexecutions,
            int timeout,
            StarttlsType starttlsType,
            List<ProbeType> excludedProbes) {
        super(scannerDetail, reexecutions, timeout, excludedProbes);
        this.starttlsType = starttlsType;
    }

    @Override
    public BulkScanWorker<TlsScanConfig> createWorker(
            String bulkScanID,
            int parallelConnectionThreads,
            int parallelScanThreads,
            IPersistenceProvider persistenceProvider) {
        return new TlsScanWorker(
                bulkScanID,
                parallelConnectionThreads,
                this,
                parallelScanThreads,
                persistenceProvider);
    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        if (starttlsType == null) {
            throw new IllegalArgumentException("starttlsType cannot be null");
        }
        this.starttlsType = starttlsType;
    }
}
