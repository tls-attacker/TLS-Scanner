/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.data;

import java.util.concurrent.atomic.AtomicInteger;

public class BulkScanJobDetails {

    private BulkScan bulkScan;

    private AtomicInteger doneScanJobs;

    private AtomicInteger scanTimeouts;

    private AtomicInteger resultsWritten;

    public BulkScanJobDetails(BulkScan bulkScan) {
        this.bulkScan = bulkScan;
        this.doneScanJobs = new AtomicInteger(0);
        this.scanTimeouts = new AtomicInteger(0);
        this.resultsWritten = new AtomicInteger(0);
    }

    public BulkScan getBulkScan() {
        return bulkScan;
    }

    public AtomicInteger getDoneScanJobs() {
        return doneScanJobs;
    }

    public AtomicInteger getScanTimeouts() {
        return scanTimeouts;
    }

    public AtomicInteger getResultsWritten() {
        return resultsWritten;
    }
}
