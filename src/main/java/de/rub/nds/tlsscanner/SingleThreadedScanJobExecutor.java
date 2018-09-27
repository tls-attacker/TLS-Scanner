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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import me.tongfei.progressbar.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SingleThreadedScanJobExecutor extends ScanJobExecutor {

    private static final Logger LOGGER = LogManager.getLogger(SingleThreadedScanJobExecutor.class.getName());

    public SingleThreadedScanJobExecutor() {
    }
    
    private String getPaddedProbeName( String probeName){
        StringBuilder sb = new StringBuilder(probeName);
        while(sb.length() < 30){
            sb.append(" ");
        }
        return sb.toString();
    }

    @Override
    public SiteReport execute(ScannerConfig config, ScanJob scanJob) {
        
        if(config.getGeneralDelegate().isDebug()){
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
            try(ProgressBar pb = new ProgressBar("", numberOfProbes)){
                return scan(config, scanJob, pb);
            }
        }
        
            
    }
    
    private SiteReport scan(ScannerConfig config, ScanJob scanJob, ProgressBar pb){
        List<ProbeType> probeTypes = new LinkedList<>();
        List<ProbeResult> resultList = new LinkedList<>();
        
        for (TlsProbe probe : scanJob.getPhaseOneTestList()) {
            if (probe.getDanger() <= config.getDangerLevel()) {
                try {
                    if(pb != null){
                        pb.setExtraMessage("Executing " + getPaddedProbeName(probe.getProbeName()));
                    }
                    resultList.add(probe.call());
                    if(pb != null){
                        pb.step();
                    }
                } catch (Exception E) {
                    LOGGER.warn("Could not execute Probe", E);
                }
                probeTypes.add(probe.getType());
            }
        }

        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        String hostname = clientDelegate.getHost();
        SiteReport report = new SiteReport(hostname, probeTypes, config.isNoColor());
        report.setServerIsAlive(Boolean.TRUE);
        for (ProbeResult result : resultList) {
            try {
                result.merge(report);
            } catch (Exception E) {
                LOGGER.warn("Could not merge SiteReport", E);
            }
        }
        //Finished phase one starting phase 2
        //Now all basic tests are merged into the site report, so we launch phase 2 so the scanner
        //has access to basic server configuration
        for (TlsProbe probe : scanJob.getPhaseTwoTestList()) {
            probe.adjustConfig(report);
        }
        resultList = new LinkedList<>();
        for (TlsProbe probe : scanJob.getPhaseTwoTestList()) {
            if (probe.getDanger() <= config.getDangerLevel()) {
                probeTypes.add(probe.getType());
                if (probe.shouldBeExecuted(report)) {
                    try {
                        if(pb != null){
                            pb.setExtraMessage("Executing " + getPaddedProbeName(probe.getProbeName()));
                        }
                        resultList.add(probe.call());
                        if(pb != null){
                            pb.step();
                        }
                    } catch (Exception E) {
                        LOGGER.warn("Could not execute Probe", E);
                    }
                } else if (!config.isImplementation()) {
                    ProbeResult result = probe.getNotExecutedResult();
                    if (result != null) {
                        resultList.add(result);
                        if(pb != null){
                            pb.step();
                        }
                    }
                }
            }
        }
        // mergeData phase 2
        for (ProbeResult result : resultList) {
            try {
                result.merge(report);
            } catch (Exception E) {
                LOGGER.warn("Could not merge SiteReport", E);
            }
        }
        //phase 3 - afterprobes
        for (AfterProbe afterProbe : scanJob.getAfterProbes()) {
            afterProbe.analyze(report);
        }
        LOGGER.info("Finished scan for: " + hostname);
        return report;
    }

    @Override
    public void shutdown() {
    }
}
