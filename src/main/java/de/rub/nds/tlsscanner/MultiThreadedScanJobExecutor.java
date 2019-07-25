/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MultiThreadedScanJobExecutor extends ScanJobExecutor implements Observer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ScannerConfig config;

    private final ScanJob scanJob;

    private List<TlsProbe> notScheduledTasks = new LinkedList<>();

    List<Future<ProbeResult>> futureResults = new LinkedList<>();

    private final ThreadPoolExecutor executor;

    public MultiThreadedScanJobExecutor(ScannerConfig config, ScanJob scanJob, int threadCount, String prefix) {
        executor = new ThreadPoolExecutor(threadCount, threadCount, 1, TimeUnit.DAYS, new LinkedBlockingDeque<>(), new NamedThreadFactory(prefix));
        this.config = config;
        this.scanJob = scanJob;
    }

    public MultiThreadedScanJobExecutor(ScannerConfig config, ScanJob scanJob, ThreadPoolExecutor executor) {
        this.executor = executor;
        this.config = config;
        this.scanJob = scanJob;
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());
    }

    public SiteReport execute() {
        this.notScheduledTasks = new ArrayList<>(scanJob.getProbeList());

        SiteReport report = new SiteReport(config.getClientDelegate().getHost());
        //TODO check that server is online?
        report.addObserver(this);
        this.update(report, null);

        do {
            long lastMerge = System.currentTimeMillis();
            List<Future<ProbeResult>> finishedFutures = new LinkedList<>();
            for (Future<ProbeResult> result : futureResults) {
                if (result.isDone()) {
                    lastMerge = System.currentTimeMillis();
                    try {
                        ProbeResult probeResult = result.get();
                        finishedFutures.add(result);
                        if (probeResult != null) {
                            probeResult.merge(report);
                        }

                    } catch (InterruptedException | ExecutionException ex) {
                        LOGGER.error("Encountered an exceptiuon before we could merge the result", ex);
                    }
                }

                if (lastMerge + 1000 * 60 * 30 < System.currentTimeMillis()) {
                    LOGGER.error("Last result merge is more than 30 minutes ago. Starting killing threads to unblock...");
                    try {
                        ProbeResult probeResult = result.get(1, TimeUnit.MINUTES);
                        finishedFutures.add(result);
                        probeResult.merge(report);
                    } catch (InterruptedException | ExecutionException | TimeoutException ex) {
                        result.cancel(true);
                        finishedFutures.add(result);
                        LOGGER.error("Killed task...", ex);
                    }
                }
            }
            futureResults.removeAll(finishedFutures);
            update(report, this);
        } while (executor.getActiveCount() != 0 || !executor.getQueue().isEmpty());

        List<ProbeResult> resultList = new LinkedList<>();

        LOGGER.info("Did not execute the following probes:");
        for (TlsProbe probe : notScheduledTasks) {
            LOGGER.info(probe.getProbeName());
        }

        //phase 3 - collect statistics
        List<TlsProbe> allProbes = scanJob.getProbeList();
        List<ExtractedValueContainer> globalContainerList = new LinkedList<>();
        for (TlsProbe probe : allProbes) {
            List<ExtractedValueContainer> tempContainerList = probe.getWriter().getCumulatedExtractedValues();
            for (ExtractedValueContainer tempContainer : tempContainerList) {
                //Try to find the original container , if it not found add it
                ExtractedValueContainer targetContainer = null;
                for (ExtractedValueContainer globalContainer : globalContainerList) {
                    if (tempContainer.getType() == globalContainer.getType()) {
                        targetContainer = globalContainer;
                        break;
                    }
                }
                if (targetContainer == null) {
                    targetContainer = new ExtractedValueContainer(tempContainer.getType());
                    globalContainerList.add(targetContainer);
                }
                targetContainer.getExtractedValueList().addAll(tempContainer.getExtractedValueList());
            }
        }
        report.setExtractedValueContainerList(globalContainerList);
        //phase 4 - afterprobes
        for (AfterProbe afterProbe : scanJob.getAfterList()) {
            afterProbe.analyze(report);
        }
        LOGGER.info("Finished scan for: " + config.getClientDelegate().getHost());
        return report;
    }

    @Override
    public void shutdown() {
        executor.shutdown();
    }

    @Override
    public synchronized void update(Observable o, Object o1) {
        if (o != null && o instanceof SiteReport) {
            SiteReport report = (SiteReport) o;
            List<TlsProbe> newNotSchedulesTasksList = new LinkedList<>();
            for (TlsProbe probe : notScheduledTasks) {
                if (probe.shouldBeExecuted(report)) {
                    LOGGER.info("Scheduling: " + probe.getProbeName());
                    Future<ProbeResult> future = executor.submit(probe);
                    futureResults.add(future);
                } else {
                    newNotSchedulesTasksList.add(probe);
                }
            }
            this.notScheduledTasks = newNotSchedulesTasksList;
        }

    }
}
