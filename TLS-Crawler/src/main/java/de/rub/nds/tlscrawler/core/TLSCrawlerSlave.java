/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * A basic TLS crawler slave implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TLSCrawlerSlave extends TLSCrawler {
    private static int NO_THREADS = 256;
    private List<Thread> threads;

    public TLSCrawlerSlave(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, List<IScan> scans) {
        super(orchestrationProvider, persistenceProvider, scans);

        threads = new LinkedList<>();

        for (int i = 0; i < NO_THREADS; i++) {
            Thread thread = new Thread(new CoordinationLoop(this), String.format("SimpleCrawlerSlave-%d", i));
            thread.start();
            this.threads.add(thread);
        }
    }

    private class CoordinationLoop implements Runnable {
        private Logger LOG = LoggerFactory.getLogger(CoordinationLoop.class);

        private TLSCrawler crawler;

        public CoordinationLoop(TLSCrawler crawler) {
            this.crawler = crawler;
        }

        @Override
        public void run() {
            //LOG.debug("run() - Started.");

            for (;;) {
                UUID taskId = this.crawler.getOrchestrationProvider().getScanTask();

                IScanTask raw = this.crawler.getPersistenceProvider().getScanTask(taskId);
                ScanTask task;

                if (raw != null) {
                    //LOG.debug("Task started.");
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
                    //LOG.debug("Task completed.");
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
