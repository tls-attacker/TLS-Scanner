/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.Slave;
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

    private static int STANDARD_NO_THREADS = 500;
    private static int MIN_NO_TO_PERSIST = 64;
    private static int ITERATIONS_TO_IGNORE_BULK_LIMITS = 10;
    private static int ORG_THREAD_SLEEP_MILLIS = 6000;

    private int noThreads;
    private int newFetchLimit;
    private int fetchAmount;
    private List<Thread> threads;
    private TlsCrawlerSlaveOrgThread orgThread;
    private SlaveStats slaveStats;
    private SynchronizedTaskRouter synchronizedTaskRouter;

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     */
    public TlsCrawlerSlave(String instanceId,
                           IOrchestrationProvider orchestrationProvider,
                           IPersistenceProvider persistenceProvider,
                           Collection<IScan> scans) {
        this(instanceId, orchestrationProvider, persistenceProvider, scans, STANDARD_NO_THREADS);
    }

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     * @param noThreads Number of worker threads the crawler slave should use.
     */
    public TlsCrawlerSlave(String instanceId,
                           IOrchestrationProvider orchestrationProvider,
                           IPersistenceProvider persistenceProvider,
                           Collection<IScan> scans,
                           int noThreads) {
        super(instanceId, orchestrationProvider, persistenceProvider, scans);

        this.noThreads = noThreads;
        this.newFetchLimit = 3 * noThreads;
        this.fetchAmount = 2 * noThreads;

        LOG.trace("Constructor()");

        this.synchronizedTaskRouter = new SynchronizedTaskRouter();
        this.slaveStats = new SlaveStats(0, 0);
        this.threads = new LinkedList<>();

        for (int i = 0; i < this.noThreads; i++) {
            Thread t = new SlaveWorkerThread(this.getInstanceId(), this.synchronizedTaskRouter, this);
            t.start();
            this.threads.add(t);
        }

        this.orgThread = new TlsCrawlerSlaveOrgThread(
                this.slaveStats,
                this,
                this,
                this.synchronizedTaskRouter,
                this.newFetchLimit,
                this.fetchAmount);
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

        private int newFetchLimit;
        private int fetchAmount;
        private SynchronizedTaskRouter synchronizedTaskRouter;
        private IOrganizer organizer;
        private IScanProvider scanProvider;
        private SlaveStats stats;

        public TlsCrawlerSlaveOrgThread(SlaveStats stats,
                                        IOrganizer organizer,
                                        IScanProvider scanProvider,
                                        SynchronizedTaskRouter synchronizedTaskRouter,
                                        int newFetchLimit,
                                        int fetchAmount) {
            super(TlsCrawlerSlaveOrgThread.class.getSimpleName());

            this.stats = stats;
            this.organizer = organizer;
            this.scanProvider = scanProvider;
            this.synchronizedTaskRouter = synchronizedTaskRouter;
            this.newFetchLimit = newFetchLimit;
            this.fetchAmount = fetchAmount;
        }

        public void stopExecution() {
            this.isRunning.set(false);
        }

        @Override
        public void run() {
            this.isRunning.set(true);
            LOG.trace("run()");

            while (this.isRunning.get()) {
                // Fetch new tasks:
                if (this.synchronizedTaskRouter.getTodoCount() < this.newFetchLimit) {
                    LOG.trace("Fetching tasks.", this.getName());

                    Collection<String> taskIds = this.organizer.getOrchestrationProvider().getScanTasks(this.fetchAmount);
                    Map<String, IScanTask> tasks =  this.organizer.getPersistenceProvider().getScanTasks(taskIds);

                    for (Map.Entry<String, IScanTask> e : tasks.entrySet()) {
                        ScanTask t = (ScanTask)e.getValue();
                        t.setAcceptedTimestamp(Instant.now());
                        e.setValue(t);
                    }

                    this.synchronizedTaskRouter.addTodo(tasks.values());

                    this.stats.incrementAcceptedTaskCount(tasks.size());
                }

                // Persist task results:
                if (this.synchronizedTaskRouter.getFinishedCount() > MIN_NO_TO_PERSIST
                        || ITERATIONS_TO_IGNORE_BULK_LIMITS < this.iterations++) {
                    LOG.trace("Persisting results.");
                    Collection<IScanTask> finishedTasks = this.synchronizedTaskRouter.getFinished();

                    // TODO: Implement bulk operation @IPersistenceProvider
                    for (IScanTask t : finishedTasks) {
                        this.organizer.getPersistenceProvider().updateScanTask(t);
                        this.stats.incrementCompletedTaskCount(1);
                    }

                    this.iterations = 0;
                }

                // Check for dead worker threads and replenish:
                List<Thread> deadThreads = new LinkedList<>();
                for (Thread t : threads) {
                    if (!t.isAlive()) {
                        deadThreads.add(t);
                    }
                }

                threads.removeAll(deadThreads);

                for (int i = 0; i < deadThreads.size(); i++) {
                    Thread newThread = new SlaveWorkerThread(organizer.getInstanceId(), synchronizedTaskRouter, scanProvider);
                    newThread.start();
                    threads.add(newThread);
                }

                // (Procreate, eat,) sleep, repeat.
                try {
                    Thread.sleep(ORG_THREAD_SLEEP_MILLIS);
                } catch (InterruptedException e) {
                    // Suffer quietly.
                }
            }
        }
    }
}
