/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ISlaveStats;
import de.rub.nds.tlscrawler.data.ScanTarget;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.data.SlaveStats;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import java.net.InetAddress;
import java.net.UnknownHostException;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Take #2 - a more sophisticated slave implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerSlave extends TlsCrawler implements ITlsCrawlerSlave {

    private static Logger LOG = LogManager.getLogger();

    private static int STANDARD_NO_THREADS = 500;
    private static int MIN_NO_TO_PERSIST = 10;
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
     * @param port
     */
    public TlsCrawlerSlave(String instanceId,
            IOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            Collection<IScan> scans, int port) {
        this(instanceId, orchestrationProvider, persistenceProvider, scans, port, STANDARD_NO_THREADS);
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
            Collection<IScan> scans, int port, int noThreads) {
        super(instanceId, orchestrationProvider, persistenceProvider, scans, port);
        this.noThreads = noThreads;
        this.newFetchLimit = 1000;
        this.fetchAmount = 5000;

        LOG.trace("Constructor()");

        this.synchronizedTaskRouter = new SynchronizedTaskRouter();
        this.slaveStats = new SlaveStats(0, 0);
        this.threads = new LinkedList<>();

        for (int i = 0; i < this.noThreads; i++) {
            Thread t = new SlaveWorkerThread(this.getInstanceId(), this.synchronizedTaskRouter, this);
            t.start();
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

    @Override
    public Collection<IScan> getScans() {
        return scans;
    }

    @Override
    public int getPort() {
        return port;
    }

    private class TlsCrawlerSlaveOrgThread extends Thread {

        private AtomicBoolean isRunning = new AtomicBoolean(false);
        private int iterations = 0;
        private long lastBlacklistUpdate = System.currentTimeMillis();
        private int newFetchLimit;
        private int fetchAmount;
        private SynchronizedTaskRouter synchronizedTaskRouter;
        private IOrganizer organizer;
        private IScanProvider scanProvider;
        private SlaveStats stats;
        private ExecutorService dnsPool;
        private List<Future<ScanTarget>> futureDnsResults;

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
            dnsPool = new ScheduledThreadPoolExecutor(100);
            futureDnsResults = new LinkedList<>();
        }

        public void stopExecution() {
            this.isRunning.set(false);
        }

        @Override
        public void run() {
            this.isRunning.set(true);
            LOG.trace("run()");

            while (this.isRunning.get()) {
                try {
                    // Fetch new tasks:
                    if (this.synchronizedTaskRouter.getTodoCount() < this.newFetchLimit) {
                        LOG.info("Fetching tasks: {}", this.getName());
                        Collection<String> targetString = this.organizer.getOrchestrationProvider().getScanTasks(this.fetchAmount);
                        LOG.info("#Fetched: {}", targetString.size());

                        for (String tempString : targetString) {
                            futureDnsResults.add(dnsPool.submit(new DnsThread(tempString, port)));
                        }
                    }
                    // Persist task results:
                    if (this.synchronizedTaskRouter.getFinishedCount() > MIN_NO_TO_PERSIST
                            || ((ITERATIONS_TO_IGNORE_BULK_LIMITS < this.iterations++) && this.synchronizedTaskRouter.getFinishedCount() != 0)) {
                        LOG.trace("Persisting results.");
                        List<ScanTask> finishedTasks = this.synchronizedTaskRouter.getFinished();
                        LOG.info("Storing results");
                        this.organizer.getPersistenceProvider().insertScanTasks(finishedTasks);
                        this.stats.incrementCompletedTaskCount(finishedTasks.size());
                        this.iterations = 0;
                    }

                    for (Future<ScanTarget> future : futureDnsResults) {
                        String taskId = UUID.randomUUID().toString();
                        ScanTarget target = future.get();
                        if (organizer.getOrchestrationProvider().isBlacklisted(target)) {
                            String name = target.getHostname() != null ? target.getHostname() : target.getIp();
                            LOG.info("Not scanning: {}", name);
                        } else {
                            ScanTask task = new ScanTask(taskId, organizer.getInstanceId(), Instant.now(), target, scanProvider.getScans());
                            this.synchronizedTaskRouter.addTodo(task);
                            this.stats.incrementAcceptedTaskCount(1);
                        }
                    }
                    futureDnsResults = new LinkedList<>();
                    // (Procreate, eat,) sleep, repeat.
                    try {
                        LOG.info("Sleeping");
                        Thread.sleep(ORG_THREAD_SLEEP_MILLIS);
                    } catch (InterruptedException e) {
                        // Suffer quietly.
                    }
                } catch (Exception E) {
                    E.printStackTrace();
                }
            }
        }
    }
}
