/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.constant.Status;
import java.io.Serializable;

public class ScanJob implements Serializable {

    private ScanTarget scanTarget;

    private ScanConfig scanConfig;

    private String bulkScanId;

    private boolean isMonitored;

    private String dbName;

    private String collectionName;

    private Status status;

    public ScanJob(
            ScanTarget scanTarget,
            ScanConfig scanConfig,
            String bulkScanId,
            boolean isMonitored,
            String dbName,
            String collectionName,
            Status status) {
        this.scanTarget = scanTarget;
        this.scanConfig = scanConfig;
        this.bulkScanId = bulkScanId;
        this.isMonitored = isMonitored;
        this.dbName = dbName;
        this.collectionName = collectionName;
        this.status = status;
    }

    public ScanTarget getScanTarget() {
        return scanTarget;
    }

    public ScanConfig getScanConfig() {
        return scanConfig;
    }

    public String getBulkScanId() {
        return bulkScanId;
    }

    public boolean isMonitored() {
        return isMonitored;
    }

    public String getDbName() {
        return dbName;
    }

    public String getCollectionName() {
        return collectionName;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }
}
