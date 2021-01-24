/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlscrawler.scans.IScan;
import java.io.Serializable;
import java.time.Instant;
import org.bson.Document;

/**
 * Scan task implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTask implements IScanTask, Serializable {

    private String _id;
    private String instanceId;
    @JsonIgnore
    private Instant acceptedTimestamp;
    @JsonIgnore
    private Instant startedTimestamp;
    @JsonIgnore
    private Instant completedTimestamp;
    private ScanTarget scanTarget;
    @JsonIgnore
    private IScan scan;
    @JsonIgnore
    private ScanJob scanJob;
    private Document result;

    public ScanTask(String id,
                    String instanceId,
                    Instant acceptedTimestamp,
                    ScanTarget scanTarget,
                    IScan scan, ScanJob scanJob) {
        this._id = id;
        this.instanceId = instanceId;
        this.acceptedTimestamp = acceptedTimestamp;
        this.scanTarget = scanTarget;
        this.result = null;
        this.startedTimestamp = null;
        this.completedTimestamp = null;
        this.scan = scan;
        this.scanJob = scanJob;
    }

    public ScanJob getScanJob() {
        return scanJob;
    }

    public void setScanJob(ScanJob scanJob) {
        this.scanJob = scanJob;
    }

    @JsonProperty("_id")
    @Override
    public String getId() {
        return this._id;
    }

    @JsonProperty("_id")
    public void setId(String _id) {
        this._id = _id;
    }

    @Override
    public String getInstanceId() {
        return this.instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    @Override
    public Instant getStartedTimestamp() {
        return startedTimestamp;
    }

    public void setStartedTimestamp(Instant startedTimestamp) {
        this.startedTimestamp = startedTimestamp;
    }

    @Override
    public Instant getAcceptedTimestamp() {
        return this.acceptedTimestamp;
    }

    public void setAcceptedTimestamp(Instant acceptedTimestamp) {
        this.acceptedTimestamp = acceptedTimestamp;
    }

    @Override
    public Instant getCompletedTimestamp() {
        return completedTimestamp;
    }

    public void setCompletedTimestamp(Instant completedTimestamp) {
        this.completedTimestamp = completedTimestamp;
    }

    @Override
    public IScan getScan() {
        return scan;
    }

    public void setScan(IScan scan) {
        this.scan = scan;
    }

    @Override
    public Document getResult() {
        return result;
    }

    @Override
    public void setResult(Document result) {
        this.result = result;
    }

    @Override
    public ScanTarget getScanTarget() {
        return scanTarget;
    }

    public void setScanTarget(ScanTarget scanTarget) {
        this.scanTarget = scanTarget;
    }

}
