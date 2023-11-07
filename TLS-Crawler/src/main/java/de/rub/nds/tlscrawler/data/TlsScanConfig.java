/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.crawler.data.ScanConfig;
import de.rub.nds.crawler.data.ScanJob;
import de.rub.nds.crawler.orchestration.IOrchestrationProvider;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.crawler.scans.Scan;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.scans.TlsScan;

public class TlsScanConfig extends ScanConfig {
    private StarttlsType starttlsType;

    public TlsScanConfig(
            ScannerDetail scannerDetail, int reexecutions, int timeout, StarttlsType starttlsType) {
        super(scannerDetail, reexecutions, timeout);
        this.starttlsType = starttlsType;
    }

    @Override
    public Scan createRunnable(
            ScanJob scanJob,
            IOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            int parallelProbeThreads) {
        return new TlsScan(
                scanJob, orchestrationProvider, persistenceProvider, parallelProbeThreads);
    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }
}
