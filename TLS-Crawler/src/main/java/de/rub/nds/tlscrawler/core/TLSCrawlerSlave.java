/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScan;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A basic TLS crawler slave implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TLSCrawlerSlave extends TLSCrawler {
    private Thread coordinatorThread;

    public TLSCrawlerSlave(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, List<IScan> scans) {
        super(orchestrationProvider, persistenceProvider, scans);

        this.coordinatorThread = new Thread(new CoordinationLoop(this), "SimpleCrawlerSlave-1");
        this.coordinatorThread.start();
    }

    private class CoordinationLoop implements Runnable {
        private TLSCrawler crawler;

        public CoordinationLoop(TLSCrawler crawler) {
            this.crawler = crawler;
        }

        @Override
        public void run() {
            for (;;) {
                UUID taskId = this.crawler.getOrchestrationProvider().getScanTask();

                IScanTask raw = this.crawler.getPersistenceProvider().getScanTask(taskId);
                ScanTask task;

                if (raw != null) {
                    task = ScanTask.copyFrom(raw);
                    task.setAcceptedTimestamp(Instant.now());

                    task.setStartedTimestamp(Instant.now());

                    for (String scan : task.getScans()) {
                        IScan scanInstance = this.crawler.getScanByName(scan);
                        Object result = scanInstance.scan(task.getScanTarget());
                        task.addResult(scan, result);
                    }

                    task.setCompletedTimestamp(Instant.now());

                    this.crawler.getPersistenceProvider().save(task);
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
