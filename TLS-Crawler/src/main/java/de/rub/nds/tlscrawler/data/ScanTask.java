/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlsscanner.report.SiteReport;
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
public class ScanTask implements IScanTask {

    private static Logger LOG = LoggerFactory.getLogger(ScanTask.class);

    private String id;
    private String scanId;
    private String instanceId;
    private Instant createdTimestamp;
    private Instant acceptedTimestamp;
    private Instant startedTimestamp;
    private Instant completedTimestamp;
    private String targetIp;
    private Collection<Integer> ports;
    private Collection<String> scans;
    private Document result;

    public ScanTask(String id,
            String scanId,
            String instanceId,
            Instant createdTimestamp,
            Instant acceptedTimestamp,
            Instant startedTimestamp,
            Instant completedTimestamp,
            String targetIp,
            Collection<Integer> ports,
            Collection<String> scans) {
        this.id = id;
        this.scanId = scanId;
        this.instanceId = instanceId;
        this.createdTimestamp = createdTimestamp;
        this.acceptedTimestamp = acceptedTimestamp;
        this.startedTimestamp = startedTimestamp;
        this.completedTimestamp = completedTimestamp;
        this.targetIp = targetIp;
        this.ports = ports;
        this.scans = scans;
        this.result = null;
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
    public String getInstanceId() {
        return this.instanceId;
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
    public Document getResult() {
        return result;
    }

    public void setResult(Document result) {
        this.result = result;
    }

    public static ScanTask copyFrom(IScanTask scan) {
        if (scan == null) {
            LOG.error("copyFrom() - 'scan' must not be null.");
            throw new IllegalArgumentException("'scan' must not be null.");
        }

        return new ScanTask(
                scan.getId(),
                scan.getScanId(),
                scan.getInstanceId(),
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
