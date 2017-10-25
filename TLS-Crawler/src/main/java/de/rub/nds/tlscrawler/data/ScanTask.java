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
import java.util.Map;
import java.util.UUID;

/**
 * Scan task implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTask implements IScanTask {
    private static Logger LOG = LoggerFactory.getLogger(ScanTask.class);

    private UUID id;
    private Instant createdTimestamp;
    private Instant acceptedTimestamp;
    private Instant startedTimestamp;
    private Instant completedTimestamp;
    private String targetIp;
    private Collection<Integer> ports;
    private Collection<String> scans;
    private Map<String, Object> results;

    public ScanTask(UUID id,
                    Instant createdTimestamp,
                    Instant acceptedTimestamp,
                    Instant startedTimestamp,
                    Instant completedTimestamp,
                    String targetIp,
                    Collection<Integer> ports,
                    Collection<String> scans) {
        this.id = id;
        this.createdTimestamp = createdTimestamp;
        this.acceptedTimestamp = acceptedTimestamp;
        this.startedTimestamp = startedTimestamp;
        this.completedTimestamp = completedTimestamp;
        this.targetIp = targetIp;
        this.ports = ports;
        this.scans = scans;

        this.results = new HashMap<>();
    }

    @Override
    public UUID getId() {
        return this.id;
    }

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
    public Map<String, Object> getResults() {
        return this.results;
    }

    public void addResult(String scanName, Object result) {
        this.results.put(scanName, result);
    }

    public static ScanTask copyFrom(IScanTask scan) {
        if (scan == null) {
            LOG.error("copyFrom() - 'scan' must not be null.");
            throw new IllegalArgumentException("'scan' must not be null.");
        }

        return new ScanTask(
                scan.getId(),
                scan.getCreatedTimestamp(),
                scan.getAcceptedTimestamp(),
                scan.getStartedTimestamp(),
                scan.getCompletedTimestamp(),
                scan.getTargetIp(),
                scan.getPorts(),
                scan.getScans());
    }
}
