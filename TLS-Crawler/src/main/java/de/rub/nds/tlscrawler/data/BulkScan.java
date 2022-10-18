/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.core.Controller;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import org.mongojack.ObjectId;

import javax.persistence.Id;
import java.io.Serializable;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.Instant;

public class BulkScan implements Serializable {

    @ObjectId
    @Id
    private String _id;

    private String name;

    private String collectionName;

    private ScanConfig scanConfig;

    private boolean monitored;

    private boolean finished;

    private long startTime;

    private long endTime;

    private int targetsGiven;

    private int scanJobsPublished;

    private int scanTimeouts;

    private int resultsWritten;

    private String notifyUrl;

    private String scannerVersion;

    private String crawlerVersion;

    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm");

    private BulkScan() {
    }

    public BulkScan(String name, ScanConfig scanConfig, long startTime, boolean monitored, String notifyUrl) {
        this.scannerVersion = TlsServerScanner.class.getPackage().getImplementationVersion();
        this.crawlerVersion = Controller.class.getPackage().getImplementationVersion();
        this.name = name;
        this.scanConfig = scanConfig;
        this.finished = false;
        this.startTime = startTime;
        this.monitored = monitored;
        this.collectionName = name + "_" + dateFormat.format(Date.from(Instant.ofEpochMilli(startTime)));
        this.notifyUrl = notifyUrl;
    }

    @ObjectId
    public String getId() {
        return this._id;
    }

    public String getName() {
        return this.name;
    }

    public String getCollectionName() {
        return this.collectionName;
    }

    public ScanConfig getScanConfig() {
        return this.scanConfig;
    }

    public boolean isMonitored() {
        return this.monitored;
    }

    public boolean isFinished() {
        return this.finished;
    }

    public long getStartTime() {
        return this.startTime;
    }

    public long getEndTime() {
        return this.endTime;
    }

    public int getTargetsGiven() {
        return this.targetsGiven;
    }

    public int getScanJobsPublished() {
        return this.scanJobsPublished;
    }

    public int getScanTimeouts() {
        return this.scanTimeouts;
    }

    public int getResultsWritten() {
        return this.resultsWritten;
    }

    public String getNotifyUrl() {
        return this.notifyUrl;
    }

    public String getScannerVersion() {
        return this.scannerVersion;
    }

    public String getCrawlerVersion() {
        return this.crawlerVersion;
    }

    @ObjectId
    public void setId(String _id) {
        this._id = _id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setCollectionName(String collectionName) {
        this.collectionName = collectionName;
    }

    public void setScanConfig(ScanConfig scanConfig) {
        this.scanConfig = scanConfig;
    }

    public void setMonitored(boolean monitored) {
        this.monitored = monitored;
    }

    public void setFinished(boolean finished) {
        this.finished = finished;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }

    public void setTargetsGiven(int targetsGiven) {
        this.targetsGiven = targetsGiven;
    }

    public void setScanJobsPublished(int scanJobsPublished) {
        this.scanJobsPublished = scanJobsPublished;
    }

    public void setScanTimeouts(int scanTimeouts) {
        this.scanTimeouts = scanTimeouts;
    }

    public void setResultsWritten(int resultsWritten) {
        this.resultsWritten = resultsWritten;
    }

    public void setNotifyUrl(String notifyUrl) {
        this.notifyUrl = notifyUrl;
    }

    public void setScannerVersion(String scannerVersion) {
        this.scannerVersion = scannerVersion;
    }

    public void setCrawlerVersion(String crawlerVersion) {
        this.crawlerVersion = crawlerVersion;
    }
}
