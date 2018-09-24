/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import me.tongfei.progressbar.ProgressBarStyle;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MultiThreadedScanJobExecutor extends ScanJobExecutor {

    private static final Logger LOGGER = LogManager.getLogger(MultiThreadedScanJobExecutor.class.getName());

    private final ExecutorService executor;

    public MultiThreadedScanJobExecutor(int threadCount) {
        executor = Executors.newFixedThreadPool(threadCount);
    }

    public MultiThreadedScanJobExecutor(ExecutorService executor) {
        this.executor = executor;
    }

    public SiteReport execute(ScannerConfig config, ScanJob scanJob) {
        List<ProbeType> probeTypes = new LinkedList<>();

        try(ProgressBar pb = new ProgressBar("", (scanJob.getPhaseOneTestList().size()+scanJob.getPhaseTwoTestList().size()))){
            pb.setExtraMessage("Executing Probes");
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
                    LOGGER.warn("Encoutered Exception while retrieving probeResult");
                    ex.printStackTrace();
                    LOGGER.warn(ex);
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
                    if (probe.shouldBeExecuted(report)) {
                        futureResults.add(executor.submit(probe));
                    } else if (!config.isImplementation()) {
                        ProbeResult result = probe.getNotExecutedResult();
                        if (result != null) {
                            resultList.add(result);
                            pb.step();
                        }
                    }
                }
            }
            
            checkProbesDone(futureResults, pb);
            
            for (Future<ProbeResult> probeResult : futureResults) {
                try {
                    resultList.add(probeResult.get());
                } catch (InterruptedException | ExecutionException ex) {
                    LOGGER.warn("Encoutered Exception while retrieving probeResult");
                    ex.printStackTrace();
                    LOGGER.warn(ex);
                }
            }
            // mergeData phase 2
            for (ProbeResult result : resultList) {
                result.merge(report);
            }
            //phase 3 - afterprobes
            for (AfterProbe afterProbe : scanJob.getAfterProbes()) {
                afterProbe.analyze(report);
            }
            executor.shutdown();
            pb.setExtraMessage("Finished");
            return report;
        }
    }
    
    private void checkProbesDone(List<Future<ProbeResult>> futureResults, ProgressBar pb){
        boolean isNotReady = true;
        int done = 0;
        int tempDone = 0;
        while (isNotReady) {
            tempDone = 0;
            for (Future<ProbeResult> probeResult : futureResults) {
                if (probeResult.isDone()) {
                    tempDone++;
                }
                if (done < tempDone) {
                    pb.step();
                    done = tempDone;
                    if (done == futureResults.size()) {
                        isNotReady = false;
                    }
                }
            }
        }
    }   
}
