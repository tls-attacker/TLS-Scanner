/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;

/**
 * Scan task implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTask implements IScanTask {
    private static Logger LOG = LoggerFactory.getLogger(ScanTask.class);

    private String id;
    private String scanId;
    private String slaveId;
    private Instant createdTimestamp;
    private Instant acceptedTimestamp;
    private Instant startedTimestamp;
    private Instant completedTimestamp;
    private String targetIp;
    private Collection<Integer> ports;
    private Collection<String> scans;
    private Collection<IScanResult> results;

    public ScanTask(String id,
                    String scandId,
                    String slaveId,
                    Instant createdTimestamp,
                    Instant acceptedTimestamp,
                    Instant startedTimestamp,
                    Instant completedTimestamp,
                    String targetIp,
                    Collection<Integer> ports,
                    Collection<String> scans) {
        this.id = id;
        this.scanId = scandId;
        this.slaveId = slaveId;
        this.createdTimestamp = createdTimestamp;
        this.acceptedTimestamp = acceptedTimestamp;
        this.startedTimestamp = startedTimestamp;
        this.completedTimestamp = completedTimestamp;
        this.targetIp = targetIp;
        this.ports = ports;
        this.scans = scans;

        this.results = new LinkedList<>();
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getScanId() {
        return this.scanId;
    }

    @Override
    public String getSlaveId() { return this.slaveId; }

    @Override
    public Instant getCreatedTimestamp() {
        return this.createdTimestamp;
    }

    public void setCreatedTimestamp(Instant timestamp) {
        this.createdTimestamp = timestamp;
    }

    @Override
    public Instant getAcceptedTimestamp() {
        return this.acceptedTimestamp;
    }

    public void setAcceptedTimestamp(Instant timestamp) {
        this.acceptedTimestamp = timestamp;
    }

    @Override
    public Instant getStartedTimestamp() {
        return this.startedTimestamp;
    }

    public void setStartedTimestamp(Instant timestamp) {
        this.startedTimestamp = timestamp;
    }

    @Override
    public Instant getCompletedTimestamp() {
        return this.completedTimestamp;
    }

    public void setCompletedTimestamp(Instant timestamp) {
        this.completedTimestamp = timestamp;
    }

    @Override
    public String getTargetIp() {
        return this.targetIp;
    }

    public void setTargetIp(String ip) {
        this.targetIp = ip;
    }

    @Override
    public Collection<Integer> getPorts() {
        return this.ports;
    }

    @Override
    public Collection<String> getScans() {
        return this.scans;
    }

    @Override
    public IScanTarget getScanTarget() {
        return new ScanTarget(this.targetIp, this.ports);
    }

    @Override
    public Collection<IScanResult> getResults() {
        return this.results;
    }

    public void addResult(IScanResult result) {
        this.results.add(result);
    }

    public static ScanTask copyFrom(IScanTask scan) {
        if (scan == null) {
            LOG.error("copyFrom() - 'scan' must not be null.");
            throw new IllegalArgumentException("'scan' must not be null.");
        }

        return new ScanTask(
                scan.getId(),
                scan.getScanId(),
                scan.getSlaveId(),
                scan.getCreatedTimestamp(),
                scan.getAcceptedTimestamp(),
                scan.getStartedTimestamp(),
                scan.getCompletedTimestamp(),
                scan.getTargetIp(),
                new LinkedList(scan.getPorts()),
                new LinkedList(scan.getScans())
        );
    }
}
