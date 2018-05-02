/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.utility.IAddressIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Implements scan task generation for parallelization in TlsCrawlerMaster.
 *
 * @author janis.fliegenschmidt@rub.de
 */
class TaskGeneratorThread extends Thread {
    private static Logger LOG = LoggerFactory.getLogger(TaskGeneratorThread.class);

    private List<String> scans;
    private IAddressIterator targets;
    private List<Integer> ports;
    private String scanId;
    private IOrganizer organizer;

    private boolean interrupted = false;

    public TaskGeneratorThread(
            List<String> scans,
            IAddressIterator targets,
            List<Integer> ports,
            String scanId,
            IOrganizer organizer) {
        this.scans = scans;
        this.targets = targets;
        this.ports = ports;
        this.scanId = scanId;
        this.organizer = organizer;
    }

    @Override
    public void run() {
        for (String target : this.targets) {
            if (this.interrupted) {
                break;
            }

            String taskId = UUID.randomUUID().toString();

            IScanTask newTask = new ScanTask(
                    taskId,
                    Instant.now(),
                    null,
                    null,
                    null,
                    target,
                    this.ports,
                    this.scans);

            this.organizer.getPersistenceProvider().setUpScanTask(newTask);
            this.organizer.getOrchestrationProvider().addScanTask(newTask.getId());
        }
    }

    public void interrupt() {
        this.interrupted = true;
    }
}
