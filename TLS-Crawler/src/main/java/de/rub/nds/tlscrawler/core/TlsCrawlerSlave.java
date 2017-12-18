/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ISlaveStats;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.data.SlaveStats;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Take #2 - a more sophisticated slave implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerSlave extends TlsCrawler implements ITlsCrawlerSlave {
    private static Logger LOG = LoggerFactory.getLogger(TlsCrawlerSlave.class);

    private static int NO_THREADS = 256;
    private static int NEW_FETCH_LIMIT = NO_THREADS * 3;
    private static int FETCH_AMOUNT = NO_THREADS * 2;
    private static int MIN_NO_TO_PERSIST = 64;
    private static int ITERATIONS_TO_IGNORE_BULK_LIMITS = 10;
    private static int ORG_THREAD_SLEEP_MILLIS = 6000;

    private List<Thread> threads;
    private TlsCrawlerSlaveOrgThread orgThread;
    private SlaveStats slaveStats;
    private SynchronizedTaskRouter synchronizedTaskRouter;

    /**
     * TLS-Crawler constructor.
     *
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     */
    public TlsCrawlerSlave(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, List<IScan> scans) {
        super(orchestrationProvider, persistenceProvider, scans);

        LOG.trace("Constructor()");

        this.synchronizedTaskRouter = new SynchronizedTaskRouter();
        this.slaveStats = new SlaveStats(0, 0);
        this.threads = new LinkedList<>();

        for (int i = 0; i < NO_THREADS; i++) {
            Thread t = new SlaveWorkerThread(this.synchronizedTaskRouter, this);
            t.start();
            this.threads.add(t);
        }

        this.orgThread = new TlsCrawlerSlaveOrgThread(this, this.synchronizedTaskRouter);
    }

    @Override
    public void start() {
        LOG.trace("start()");
        this.orgThread.start();
    }

    @Override
    public ISlaveStats getStats() {
        return SlaveStats.copyFrom(this.slaveStats);
    }

    private class TlsCrawlerSlaveOrgThread extends Thread {
        private AtomicBoolean isRunning = new AtomicBoolean(false);
        private int iterations = 0;

        private SynchronizedTaskRouter synchronizedTaskRouter;
        private IOrganizer organizer;

        public TlsCrawlerSlaveOrgThread(IOrganizer organizer, SynchronizedTaskRouter synchronizedTaskRouter) {
            super(TlsCrawlerSlaveOrgThread.class.getSimpleName());
            this.organizer = organizer;
            this.synchronizedTaskRouter = synchronizedTaskRouter;
        }

        public void stopExecution() {
            this.isRunning.set(false);
        }

        @Override
        public void run() {
            this.isRunning.set(true);
            LOG.trace("run()");

            while (this.isRunning.get()) {
                if (this.synchronizedTaskRouter.getTodoCount() < NEW_FETCH_LIMIT) {
                    LOG.trace("Fetching tasks.", this.getName());

                    Collection<String> taskIds = this.organizer.getOrchestrationProvider().getScanTasks(FETCH_AMOUNT);
                    Map<String, IScanTask> tasks =  this.organizer.getPersistenceProvider().getScanTasks(taskIds);

                    for (Map.Entry<String, IScanTask> e : tasks.entrySet()) {
                        ScanTask t = (ScanTask)e.getValue();
                        t.setAcceptedTimestamp(Instant.now());
                        e.setValue(t);
                    }

                    this.synchronizedTaskRouter.addTodo(tasks.values());
                }

                if (this.synchronizedTaskRouter.getFinishedCount() > MIN_NO_TO_PERSIST
                        || ITERATIONS_TO_IGNORE_BULK_LIMITS < this.iterations++) {
                    LOG.trace("Persisting results.");
                    Collection<IScanTask> finishedTasks = this.synchronizedTaskRouter.getFinished();

                    // TODO: Implement bulk operation @IPersistenceProvider
                    for (IScanTask t : finishedTasks) {
                        this.organizer.getPersistenceProvider().updateScanTask(t);
                    }

                    this.iterations = 0;
                }

                try {
                    Thread.sleep(ORG_THREAD_SLEEP_MILLIS);
                } catch (InterruptedException e) {
                    // Suffer quietly.
                }
            }
        }
    }
}
