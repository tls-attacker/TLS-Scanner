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
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import me.tongfei.progressbar.ProgressBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MultiThreadedScanJobExecutor extends ScanJobExecutor {

    private static final Logger LOGGER = LogManager.getLogger(MultiThreadedScanJobExecutor.class.getName());

    private final ExecutorService executor;

    public MultiThreadedScanJobExecutor(int threadCount, String prefix) {
        executor = Executors.newFixedThreadPool(threadCount, new NamedThreadFactory(prefix));
    }

    public MultiThreadedScanJobExecutor(ExecutorService executor) {
        this.executor = executor;
    }

    public SiteReport execute(ScannerConfig config, ScanJob scanJob) {

        if (config.getGeneralDelegate().isDebug() || config.isNoProgressbar()) {
            return scan(config, scanJob, null);
        } else {
            int numberOfProbes = 0;
            for (TlsProbe probe : scanJob.getPhaseOneTestList()) {
                if (probe.getDanger() <= config.getDangerLevel()) {
                    numberOfProbes++;
                }
            }
            for (TlsProbe probe : scanJob.getPhaseTwoTestList()) {
                if (probe.getDanger() <= config.getDangerLevel()) {
                    numberOfProbes++;
                }
            }
            try (ProgressBar pb = new ProgressBar("", numberOfProbes)) {
                return scan(config, scanJob, pb);
            }
        }
    }

    private SiteReport scan(ScannerConfig config, ScanJob scanJob, ProgressBar pb) {
        List<ProbeType> probeTypes = new LinkedList<>();
        if (pb != null) {
            pb.setExtraMessage("Executing Probes");
        }
        List<Future<ProbeResult>> futureResults = new LinkedList<>();
        for (TlsProbe probe : scanJob.getPhaseOneTestList()) {
            if (probe.getDanger() <= config.getDangerLevel()) {
                futureResults.add(executor.submit(probe));
                probeTypes.add(probe.getType());
            }
        }
        List<ProbeResult> resultList = new LinkedList<>();

        checkProbesDone(futureResults, pb);

        for (Future<ProbeResult> probeResult : futureResults) {
            try {
                resultList.add(probeResult.get());
            } catch (InterruptedException | ExecutionException ex) {
                LOGGER.error("Encoutered Exception while retrieving probeResult", ex);
            }
        }

        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        String hostname = clientDelegate.getHost();
        SiteReport report = new SiteReport(hostname, probeTypes, config.isNoColor());
        report.setServerIsAlive(Boolean.TRUE);
        for (ProbeResult result : resultList) {
            result.merge(report);
        }
        //Finished phase one starting phase 2
        //Now all basic tests are merged into the site report, so we launch phase 2 so the scanner
        //has access to basic server configuration
        for (TlsProbe probe : scanJob.getPhaseTwoTestList()) {
            probe.adjustConfig(report);
        }
        futureResults = new LinkedList<>();
        resultList = new LinkedList<>();
        for (TlsProbe probe : scanJob.getPhaseTwoTestList()) {
            if (probe.getDanger() <= config.getDangerLevel()) {
                probeTypes.add(probe.getType());
                if (probe.canBeExecuted(report)) {
                    futureResults.add(executor.submit(probe));
                } else {
                    ProbeResult result = probe.getCouldNotExecuteResult();
                    if (result != null) {
                        resultList.add(result);
                        if (pb != null) {
                            pb.step();
                        }
                    }
                }
            }
        }

        checkProbesDone(futureResults, pb);

        for (Future<ProbeResult> probeResult : futureResults) {
            try {
                resultList.add(probeResult.get());
            } catch (InterruptedException | ExecutionException ex) {
                LOGGER.error("Encoutered Exception while retrieving probeResult", ex);
            }
        }
        // mergeData phase 2
        for (ProbeResult result : resultList) {
            result.merge(report);
        }
        //phase 3 - collect statistics
        List<TlsProbe> allProbes = scanJob.getJoinedProbes();
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
        LOGGER.info("Finished scan for: " + hostname);
        return report;
    }

    private void checkProbesDone(List<Future<ProbeResult>> futureResults, ProgressBar pb) {
        boolean isNotReady = true;
        int done = 0;
        int tempDone = 0;
        while (isNotReady && futureResults.size() > 0) {
            tempDone = 0;
            for (Future<ProbeResult> probeResult : futureResults) {
                if (probeResult.isDone()) {
                    tempDone++;
                }
                if (done < tempDone) {
                    if (pb != null) {
                        pb.step();
                    }
                    done = tempDone;
                    if (done == futureResults.size()) {
                        isNotReady = false;
                    }
                }
            }
        }
    }

    @Override
    public void shutdown() {
        executor.shutdown();
    }
}
