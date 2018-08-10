/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.scans.IScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Worker Thread for a more sophisticated TLS crawler slave implementation.
 *
 * // TODO: Graceful exit
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SlaveWorkerThread extends Thread {
    private static Logger LOG = LoggerFactory.getLogger(SlaveWorkerThread.class);

    private final SynchronizedTaskRouter synchronizedTaskRouter;
    private final String slaveInstanceId;

    private IScanProvider scanProvider;

    public SlaveWorkerThread(String slaveInstanceId,
                             SynchronizedTaskRouter synchronizedTaskRouter,
                             IScanProvider scanProvider) {
        this.slaveInstanceId = slaveInstanceId;
        this.synchronizedTaskRouter = synchronizedTaskRouter;
        this.scanProvider = scanProvider;
    }

    @Override
    public void run() {
        LOG.info("run() started");

        for (;;) {
            IScanTask raw = this.synchronizedTaskRouter.getTodo();

            if (raw != null) {
                LOG.trace(String.format("Started work on %s.", raw.getId()));
                this.setName("Thread - " + raw.getTargetIp());

                ScanTask todo = ScanTask.copyFrom(raw);

                todo.setStartedTimestamp(Instant.now());

                for (String scan : todo.getScans()) {
                    IScanResult result;

                    try {
                        IScan scanInstance = this.scanProvider.getScanByName(scan);
                        result = scanInstance.scan(this.slaveInstanceId, todo.getScanTarget());
                    } catch (Exception e) {
                        result = new ScanResult(scan);
                        result.addString("failedWithException", e.toString());
                    }

                    todo.addResult(result);
                }

                todo.setCompletedTimestamp(Instant.now());

                this.synchronizedTaskRouter.addFinished(todo);
            } else {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    // Suffer quietly.
                }
            }
        }
    }
}
