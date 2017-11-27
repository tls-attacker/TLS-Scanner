/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.*;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

/**
 * A basic TLS crawler slave implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerSlave extends TlsCrawler {
    private static Logger LOG = LoggerFactory.getLogger(TlsCrawlerSlave.class);

    private static int NO_THREADS = 256;
    private List<Thread> threads;
    private SlaveStats slaveStats;
    private Object statSyncRoot;

    /**
     * TLS-Crawler slave constructor.
     *
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     */
    public TlsCrawlerSlave(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, List<IScan> scans) {
        super(orchestrationProvider, persistenceProvider, scans);

        this.statSyncRoot = new Object();
        this.slaveStats = new SlaveStats(0, 0);
        this.threads = new LinkedList<>();

        LOG.debug("TlsCrawlerSlave() - Setting up worker threads.");
        for (int i = 0; i < NO_THREADS; i++) {
            Thread thread = new Thread(new TlsCrawlerSlaveWorker(this), String.format("SimpleCrawlerSlave-%d", i));
            thread.start();
            this.threads.add(thread);
        }
    }

    /**
     * @return Returns this slave's stats.
     */
    public ISlaveStats getStats() {
        synchronized (this.statSyncRoot) {
            return SlaveStats.copyFrom(this.slaveStats);
        }
    }

    /**
     * Implements logic, to be executed in parallel, of retrieving and performing scans
     * as well as persisting results.
     */
    private class TlsCrawlerSlaveWorker implements Runnable {
        private Logger LOG = LoggerFactory.getLogger(TlsCrawlerSlaveWorker.class);

        private TlsCrawler crawler;

        public TlsCrawlerSlaveWorker(TlsCrawler crawler) {
            this.crawler = crawler;
        }

        @Override
        public void run() {
            LOG.debug("run() - Started.");

            for (;;) {
                String taskId = this.crawler.getOrchestrationProvider().getScanTask();
                IScanTask raw = this.crawler.getPersistenceProvider().getScanTask(taskId);

                if (raw != null) {
                    LOG.debug("Task started.");
                    ScanTask task = ScanTask.copyFrom(raw);

                    synchronized (statSyncRoot) {
                        slaveStats.incrementAcceptedTaskCount(1);
                    }

                    task.setAcceptedTimestamp(Instant.now());

                    task.setStartedTimestamp(Instant.now());

                    for (String scan : task.getScans()) {
                        IScan scanInstance = this.crawler.getScanByName(scan);
                        IScanResult result = scanInstance.scan(task.getScanTarget());
                        task.addResult(result);
                    }

                    task.setCompletedTimestamp(Instant.now());

                    this.crawler.getPersistenceProvider().updateScanTask(task);

                    synchronized (statSyncRoot) {
                        slaveStats.incrementCompletedTaskCount(1);
                    }

                    LOG.debug("Task completed.");
                } else {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        // swallow it whole.
                    }
                }
            }
        }
    }
}
