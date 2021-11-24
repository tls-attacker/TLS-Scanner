/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

<<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/scan/ThreadedScanJobExecutor.java
package de.rub.nds.tlsscanner.serverscanner.scan;

import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsscanner.serverscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
========
package de.rub.nds.scanner.core.execution;

import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.util.ConsoleLogger;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.execution.ScanJobExecutor;
import de.rub.nds.scanner.core.execution.ScanJob;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.passive.TrackableValue;>>>>>>>>dae7150d1(reworked client scanner):Scanner-Core/src/main/java/de/rub/nds/scanner/core/execution/ThreadedScanJobExecutor.java
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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class ThreadedScanJobExecutor extends ScanJobExecutor implements Observer {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int MERGE_TIMEOUT_MS = 1000 * 60 * 30;

    private final ScannerConfig config;

    private final ScanJob scanJob;

    private List<ScannerProbe> notScheduledTasks = new LinkedList<>();

    List<Future<ProbeResult>> futureResults = new LinkedList<>();

    private final ThreadPoolExecutor executor;

    // Used for waiting for Threads in the ThreadPoolExecutor
    private final Semaphore semaphore = new Semaphore(0);

    public ThreadedScanJobExecutor(ScannerConfig config, ScanJob scanJob, int threadCount, String prefix) {
        long probeTimeout = config.getProbeTimeout();
        executor = new ScannerThreadPoolExecutor(threadCount, new NamedThreadFactory(prefix), semaphore, probeTimeout);
        this.config = config;
        this.scanJob = scanJob;
    }

    public ThreadedScanJobExecutor(ScannerConfig config, ScanJob scanJob, ThreadPoolExecutor executor) {
        this.executor = executor;
        this.config = config;
        this.scanJob = scanJob;
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());
    }

    public ScanReport execute(ScanReport report) {
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());

<<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/scan/ThreadedScanJobExecutor.java
        SiteReport report =
            new SiteReport(config.getClientDelegate().getHost(), config.getClientDelegate().getExtractedPort());
========
>>>>>>>> dae7150d1 (reworked client scanner):Scanner-Core/src/main/java/de/rub/nds/scanner/core/execution/ThreadedScanJobExecutor.java
        report.addObserver(this);

        checkForExecutableProbes(report);
        executeProbesTillNoneCanBeExecuted(report);
        updateSiteReportWithNotExecutedProbes(report);
        reportAboutNotExecutedProbes();
        collectStatistics(report);
        executeAfterProbes(report);

        LOGGER.info("Finished scan");
        return report;
    }

    private void updateSiteReportWithNotExecutedProbes(ScanReport report) {
        for (ScannerProbe probe : notScheduledTasks) {
            probe.getCouldNotExecuteResult().merge(report);
        }
    }

    private void checkForExecutableProbes(ScanReport report) {
        update(report, null);
    }

    <<<<<<<<HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/scan/ThreadedScanJobExecutor.java

    private void executeProbesTillNoneCanBeExecuted(SiteReport report) {
        while (true) {
            // handle all Finished Results
========

    private void executeProbesTillNoneCanBeExecuted(ScanReport report) {
        do {
>>>>>>>> dae7150d1 (reworked client scanner):Scanner-Core/src/main/java/de/rub/nds/scanner/core/execution/ThreadedScanJobExecutor.java
            long lastMerge = System.currentTimeMillis();
            List<Future<ProbeResult>> finishedFutures = new LinkedList<>();
            for (Future<ProbeResult> result : futureResults) {
                if (result.isDone()) {
                    lastMerge = System.currentTimeMillis();
                    try {
                        ProbeResult probeResult = result.get();
                        ConsoleLogger.CONSOLE
                            .info("+++" + probeResult.getType().getHumanReadableName() + " probe executed");
                        finishedFutures.add(result);
                        report.markProbeAsExecuted(result.get().getType());
                        if (probeResult != null) {
                            probeResult.merge(report);
                        }

                    } catch (InterruptedException | ExecutionException ex) {
                        LOGGER.error("Encountered an exception before we could merge the result. Killing the task.",
                            ex);
                        result.cancel(true);
                        finishedFutures.add(result);
                    } catch (CancellationException ex) {
                        LOGGER.info("Could not retrieve a task because it was cancelled after "
                            + config.getProbeTimeout() + " milliseconds");
                        finishedFutures.add(result);
                    }
                }
            }
            futureResults.removeAll(finishedFutures);
            int oldFutures = futureResults.size();
            // execute possible new probes
            update(report, this);
            if (futureResults.size() == 0) {
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
        for (ScannerProbe probe : notScheduledTasks) {
            LOGGER.debug(probe.getProbeName());
        }
    }

    private void collectStatistics(ScanReport report) {
        LOGGER.debug("Evaluating executed handshakes...");
        List<ScannerProbe> allProbes = scanJob.getProbeList();
        HashMap<TrackableValue, ExtractedValueContainer> containerMap = new HashMap<>();
        int stateCounter = 0;
        for (ScannerProbe probe : allProbes) {
            if (probe.getWriter() != null) {
                List<ExtractedValueContainer> tempContainerList = probe.getWriter().getCumulatedExtractedValues();
                for (ExtractedValueContainer tempContainer : tempContainerList) {
                    if (containerMap.containsKey(tempContainer.getType())) {
                        containerMap.get(tempContainer.getType()).getExtractedValueList()
                            .addAll(tempContainer.getExtractedValueList());
                    } else {
                        containerMap.put(tempContainer.getType(), tempContainer);
                    }
                }
                stateCounter += probe.getWriter().getStateCounter();
            }
        }
        report.setPerformedTcpConnections(stateCounter);
        report.setExtractedValueContainerList(containerMap);
        LOGGER.debug("Finished evaluation");
    }

    private void executeAfterProbes(ScanReport report) {
        LOGGER.debug("Analyzing data...");
        for (AfterProbe afterProbe : scanJob.getAfterList()) {
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
        if (o != null && o instanceof ScanReport) {
            ScanReport report = (ScanReport) o;
            List<ScannerProbe> newNotSchedulesTasksList = new LinkedList<>();
            for (ScannerProbe probe : notScheduledTasks) {
                if (probe.canBeExecuted(report)) {
                    probe.adjustConfig(report);
                    LOGGER.debug("Scheduling: " + probe.getProbeName());
                    Future<ProbeResult> future = executor.submit(probe);
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
