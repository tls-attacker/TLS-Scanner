/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.tlscrawler.scans.IScan;
import java.io.Serializable;

import java.time.Instant;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/**
 * Scan task implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTask implements IScanTask, Serializable {

    private static Logger LOG = LogManager.getLogger();
    
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
    private Document result;

    private ScanTask() {
    }

    public ScanTask(String id,
            String instanceId,
            Instant acceptedTimestamp,
            ScanTarget scanTarget,
            IScan scan) {
        this._id = id;
        this.instanceId = instanceId;
        this.acceptedTimestamp = acceptedTimestamp;
        this.scanTarget = scanTarget;
        this.result = null;
        this.startedTimestamp = null;
        this.completedTimestamp = null;
        this.scan = scan;
    }

    @JsonProperty("_id")
    @Override
    public String getId() {
        return this._id;
    }

    @Override
    public String getInstanceId() {
        return this.instanceId;
    }

    @Override
    public Instant getStartedTimestamp() {
        return startedTimestamp;
    }

    @Override
    public Instant getAcceptedTimestamp() {
        return this.acceptedTimestamp;
    }

    public void setCompletedTimestamp(Instant completedTimestamp) {
        this.completedTimestamp = completedTimestamp;
    }

    @Override
    public Instant getCompletedTimestamp() {
        return completedTimestamp;
    }

    @Override
    public IScan getScan() {
        return scan;
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

    @JsonProperty("_id")
    public void setId(String _id) {
        this._id = _id;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public void setAcceptedTimestamp(Instant acceptedTimestamp) {
        this.acceptedTimestamp = acceptedTimestamp;
    }

    public void setStartedTimestamp(Instant startedTimestamp) {
        this.startedTimestamp = startedTimestamp;
    }

    public void setScanTarget(ScanTarget scanTarget) {
        this.scanTarget = scanTarget;
    }

    public void setScan(IScan scan) {
        this.scan = scan;
    }

}
