/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.scans.IScan;
import java.io.Serializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import org.bson.Document;

/**
 * Scan task implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTask implements IScanTask, Serializable {

    private static Logger LOG = LoggerFactory.getLogger(ScanTask.class);

    private final String id;
    private final String instanceId;
    private final Instant acceptedTimestamp;
    private final Instant startedTimestamp;
    private Instant completedTimestamp;
    private final IScanTarget scanTarget;
    private final Collection<String> scans;
    private Document result;

    public ScanTask(String id,
            String instanceId,
            Instant acceptedTimestamp,
            IScanTarget scanTarget,
            Collection<IScan> scans) {
        this.id = id;
        this.instanceId = instanceId;
        this.acceptedTimestamp = acceptedTimestamp;
        this.scanTarget = scanTarget;
        this.scans = new LinkedList<>();
        for (IScan tempScan : scans) {
            this.scans.add(tempScan.getName());
        }
        this.result = null;
        this.startedTimestamp = null;
        this.completedTimestamp = null;
    }

    @Override
    public String getId() {
        return this.id;
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
    public Collection<String> getScans() {
        return this.scans;
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
    public IScanTarget getScanTarget() {
        return scanTarget;
    }

}
