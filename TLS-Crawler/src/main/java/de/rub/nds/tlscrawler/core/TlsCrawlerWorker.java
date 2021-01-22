/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IWorkerStats;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanTarget;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.data.WorkerStats;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.ScanHolder;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
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
public class TlsCrawlerWorker extends TlsCrawler implements ITlsCrawlerWorker {

    private static Logger LOG = LogManager.getLogger();

    private static int STANDARD_NO_THREADS = 500;
    private static int MIN_NO_TO_PERSIST = 10;
    private static int ITERATIONS_TO_IGNORE_BULK_LIMITS = 10;
    private static int ORG_THREAD_SLEEP_MILLIS = 6000;

    private int noThreads;
    private int newFetchLimit;
    private int fetchAmount;
    private List<Thread> threads;
    private TlsCrawlerWorkerOrgThread orgThread;
    private WorkerStats workerStats;
    private SynchronizedTaskRouter synchronizedTaskRouter;

    private ScanJob currentScanJob;
    private IScan currentScan;

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     */
    public TlsCrawlerWorker(String instanceId,
                            IOrchestrationProvider orchestrationProvider,
                            IPersistenceProvider persistenceProvider) {
        this(instanceId, orchestrationProvider, persistenceProvider, STANDARD_NO_THREADS);
    }

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param noThreads Number of worker threads the crawler slave should use.
     */
    public TlsCrawlerWorker(String instanceId,
                            IOrchestrationProvider orchestrationProvider,
                            IPersistenceProvider persistenceProvider, int noThreads) {
        super(instanceId, orchestrationProvider, persistenceProvider);
        this.noThreads = noThreads;
        this.newFetchLimit = 1000;
        this.fetchAmount = 5000;

        LOG.trace("Constructor()");

        this.synchronizedTaskRouter = new SynchronizedTaskRouter();
        this.workerStats = new WorkerStats(0, 0);
        this.threads = new LinkedList<>();

        for (int i = 0; i < this.noThreads; i++) {
            Thread t = new WorkerThread(this.getInstanceId(), this.synchronizedTaskRouter, this);
            t.start();
        }

        this.orgThread = new TlsCrawlerWorkerOrgThread(
                this.workerStats,
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
    public IWorkerStats getStats() {
        return WorkerStats.copyFrom(this.workerStats);
    }

    @Override
    public IScan getCurrentScan() {
        return currentScan;
    }

    private class TlsCrawlerWorkerOrgThread extends Thread {

        private AtomicBoolean isRunning = new AtomicBoolean(false);
        private int iterations = 0;
        private long lastBlacklistUpdate = System.currentTimeMillis();
        private int newFetchLimit;
        private int fetchAmount;
        private SynchronizedTaskRouter synchronizedTaskRouter;
        private IOrganizer organizer;
        private WorkerStats stats;
        private ExecutorService dnsPool;
        private List<Future<ScanTarget>> futureDnsResults;

        public TlsCrawlerWorkerOrgThread(WorkerStats stats,
                                         IOrganizer organizer,
                                         IScanProvider scanProvider,
                                         SynchronizedTaskRouter synchronizedTaskRouter,
                                         int newFetchLimit,
                                         int fetchAmount) {
            super(TlsCrawlerWorkerOrgThread.class.getSimpleName());

            this.stats = stats;
            this.organizer = organizer;
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
                        findWork();
                    }
                    // Persist task results:
                    if (this.synchronizedTaskRouter.getFinishedCount() > MIN_NO_TO_PERSIST
                            || ((ITERATIONS_TO_IGNORE_BULK_LIMITS < this.iterations++) && this.synchronizedTaskRouter.getFinishedCount() != 0)) {
                        persistResults();
                    }

                    updateTodos();
                    sleep();
                } catch (Exception E) {
                    E.printStackTrace();
                }
            }
        }

        private void sleep() {
            // (Procreate, eat,) sleep, repeat.
            try {
                LOG.info("Sleeping");
                Thread.sleep(ORG_THREAD_SLEEP_MILLIS);
            } catch (InterruptedException e) {
                // Suffer quietly.
            }
        }

        private void updateTodos() throws InterruptedException, ExecutionException {
            for (Future<ScanTarget> future : futureDnsResults) {
                String taskId = UUID.randomUUID().toString();
                ScanTarget target = future.get();
                if (organizer.getOrchestrationProvider().isBlacklisted(target)) {
                    String name = target.getHostname() != null ? target.getHostname() : target.getIp();
                    LOG.info("Not scanning: {}", name);
                } else {
                    ScanTask task = new ScanTask(taskId, organizer.getInstanceId(), Instant.now(), target, currentScan, currentScanJob);
                    this.synchronizedTaskRouter.addTodo(task);
                    this.stats.incrementAcceptedTaskCount(1);
                }
            }
            futureDnsResults = new LinkedList<>();
        }

        private void persistResults() {
            LOG.trace("Persisting results.");
            List<ScanTask> finishedTasks = this.synchronizedTaskRouter.getFinished();
            LOG.info("Storing results");

            this.organizer.getPersistenceProvider().insertScanTasks(finishedTasks);
            this.stats.incrementCompletedTaskCount(finishedTasks.size());
            this.iterations = 0;
        }

        private void findWork() {
            if (currentScanJob == null) {
                currentScanJob = lookForScanJob();
            }
            if (currentScanJob != null) {
                LOG.info("Fetching tasks: {}", this.getName());
                Collection<String> targetString = this.organizer.getOrchestrationProvider().getScanTasks(currentScanJob, this.fetchAmount);
                LOG.info("#Fetched: {}", targetString.size());
                if (targetString.isEmpty()) {
                    currentScanJob = null;
                } else {
                    for (String tempString : targetString) {
                        futureDnsResults.add(dnsPool.submit(new DnsThread(tempString, currentScanJob.getPort())));
                    }
                }
            }
        }

        private ScanJob lookForScanJob() {
            IOrchestrationProvider orchestrationProvider = organizer.getOrchestrationProvider();
            Collection<ScanJob> scanJobs = orchestrationProvider.getScanJobs();
            for (ScanJob job : scanJobs) {
                if (orchestrationProvider.getNumberOfTasks(job) > 0) {
                    currentScan = ScanHolder.createScan(job.getScan(), job.getTimeout(), noThreads, job.getReexecutions(), job.getStarttlsType());
                    return job;
                }
            }
            LOG.info("No jobs in queue are up");
            return null;
        }
    }
}
