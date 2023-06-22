/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.config.ExecutorConfig;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.passive.TrackableValue;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ThreadedScanJobExecutor<
                R extends ScanReport<R>, P extends ScannerProbe<R, P>, AP extends AfterProbe<R>>
        extends ScanJobExecutor<R> implements Observer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExecutorConfig config;

    private final ScanJob<R, P, AP> scanJob;

    private List<P> notScheduledTasks = new LinkedList<>();

    private List<Future<P>> futureResults = new LinkedList<>();

    private final ThreadPoolExecutor executor;

    // Used for waiting for Threads in the ThreadPoolExecutor
    private final Semaphore semaphore = new Semaphore(0);

    public ThreadedScanJobExecutor(
            ExecutorConfig config, ScanJob<R, P, AP> scanJob, int threadCount, String prefix) {
        long probeTimeout = config.getProbeTimeout();
        executor =
                new ScannerThreadPoolExecutor(
                        threadCount, new NamedThreadFactory(prefix), semaphore, probeTimeout);
        this.config = config;
        this.scanJob = scanJob;
    }

    public ThreadedScanJobExecutor(
            ExecutorConfig config, ScanJob<R, P, AP> scanJob, ThreadPoolExecutor executor) {
        this.executor = executor;
        this.config = config;
        this.scanJob = scanJob;
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());
    }

    @Override
    public R execute(R report) {
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());

        report.addObserver(this);

        checkForExecutableProbes(report);
        executeProbesTillNoneCanBeExecuted(report);
        updateSiteReportWithNotExecutedProbes(report);
        reportAboutNotExecutedProbes();
        collectStatistics(report);
        executeAfterProbes(report);

        LOGGER.info("Finished scan");
        report.deleteObserver(this);
        return report;
    }

    private void updateSiteReportWithNotExecutedProbes(R report) {
        for (P probe : notScheduledTasks) {
            probe.merge(report);
            report.markProbeAsUnexecuted(probe);
        }
    }

    private void checkForExecutableProbes(R report) {
        update(report, null);
    }

    private void executeProbesTillNoneCanBeExecuted(R report) {
        while (true) {
            // handle all Finished Results
            long lastMerge = System.currentTimeMillis();
            List<Future<P>> finishedFutures = new LinkedList<>();
            for (Future<P> result : futureResults) {
                if (result.isDone()) {
                    lastMerge = System.currentTimeMillis();
                    try {
                        ScannerProbe<R, P> probeResult = result.get();
                        LOGGER.info(probeResult.getType().getName() + " probe executed");
                        finishedFutures.add(result);
                        report.markProbeAsExecuted(result.get().getType());
                        probeResult.merge(report);
                    } catch (InterruptedException | ExecutionException ex) {
                        LOGGER.error(
                                "Encountered an exception before we could merge the result. Killing the task.",
                                ex);
                        result.cancel(true);
                        finishedFutures.add(result);
                    } catch (CancellationException ex) {
                        LOGGER.info(
                                "Could not retrieve a task because it was cancelled after "
                                        + config.getProbeTimeout()
                                        + " milliseconds");
                        finishedFutures.add(result);
                    }
                }
            }
            futureResults.removeAll(finishedFutures);
            // execute possible new probes
            update(report, this);
            if (futureResults.isEmpty()) {
                // nothing can be executed anymore
                return;
            } else {
                try {
                    // wait for at least one probe to finish executing before checking again
                    semaphore.acquire();
                } catch (Exception e) {
                    LOGGER.info("Interrupted while waiting for probe execution");
                }
            }
        }
    }

    private void reportAboutNotExecutedProbes() {
        LOGGER.debug("Did not execute the following probes:");
        for (P probe : notScheduledTasks) {
            LOGGER.debug(probe.getProbeName());
        }
    }

    private void collectStatistics(R report) {
        LOGGER.debug("Evaluating executed handshakes...");
        List<P> allProbes = scanJob.getProbeList();
        HashMap<TrackableValue, ExtractedValueContainer<?>> containerMap = new HashMap<>();
        int stateCounter = 0;
        for (P probe : allProbes) {
            List<ExtractedValueContainer<?>> tempContainerList =
                    probe.getWriter().getCumulatedExtractedValues();
            for (ExtractedValueContainer<?> tempContainer : tempContainerList) {
                if (containerMap.containsKey(tempContainer.getType())) {
                    // This cast should not fail because we only combine containers of the same type
                    //noinspection unchecked
                    ((List<Object>)
                                    containerMap
                                            .get(tempContainer.getType())
                                            .getExtractedValueList())
                            .addAll(tempContainer.getExtractedValueList());
                } else {
                    containerMap.put(tempContainer.getType(), tempContainer);
                }
            }
            stateCounter += probe.getWriter().getStateCounter();
        }
        report.setPerformedTcpConnections(stateCounter);
        report.setExtractedValueContainerMap(containerMap);
        LOGGER.debug("Finished evaluation");
    }

    private void executeAfterProbes(R report) {
        LOGGER.debug("Analyzing data...");
        for (AfterProbe<R> afterProbe : scanJob.getAfterList()) {
            afterProbe.analyze(report);
        }
        LOGGER.debug("Finished analysis");
    }

    @Override
    public void shutdown() {
        executor.shutdown();
    }

    @Override
    public synchronized void update(Observable o, Object o1) {
        if (o instanceof ScanReport) {
            R report = (R) o;
            List<P> newNotSchedulesTasksList = new LinkedList<>();
            for (P probe : notScheduledTasks) {
                if (probe.canBeExecuted(report)) {
                    probe.adjustConfig(report);
                    LOGGER.debug("Scheduling: " + probe.getProbeName());
                    Future<P> future = executor.submit(probe);
                    futureResults.add(future);
                } else {
                    newNotSchedulesTasksList.add(probe);
                }
            }
            this.notScheduledTasks = newNotSchedulesTasksList;
        } else {
            LOGGER.error(this.getClass().getName() + " received an update from a non-siteReport");
        }
    }
}
