/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.probe.CompressionsProbe;
import de.rub.nds.tlsscanner.probe.Cve20162107Probe;
import de.rub.nds.tlsscanner.probe.DrownProbe;
import de.rub.nds.tlsscanner.probe.EarlyCcsProbe;
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.HttpHeaderProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.MacProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.PoodleProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.probe.Tls13Probe;
import de.rub.nds.tlsscanner.probe.TlsPoodleProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.TokenbindingProbe;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.report.after.LogjamAfterprobe;
import de.rub.nds.tlsscanner.report.after.Sweet32AfterProbe;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsScanner {

    private final Logger LOGGER = LogManager.getLogger();

    private final ScanJobExecutor executor;
    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private final boolean closeAfterFinish;
    private final boolean closeAfterFinishParallel;
    private final List<TlsProbe> phaseOneTestList;
    private final List<TlsProbe> phaseTwoTestList;
    private final List<AfterProbe> afterList;

    public TlsScanner(ScannerConfig config) {
        this.executor = ScanJobExecutorFactory.getScanJobExecutor(config);
        this.config = config;
        closeAfterFinish = true;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getAggroLevel(), 3, new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.phaseOneTestList = new LinkedList<>();
        this.phaseTwoTestList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor) {
        this.config = config;
        this.executor = executor;
        closeAfterFinish = false;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getAggroLevel(), 3, new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.phaseOneTestList = new LinkedList<>();
        this.phaseTwoTestList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor, ParallelExecutor parallelExecutor) {
        this.config = config;
        this.executor = executor;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinish = false;
        closeAfterFinishParallel = false;
        this.phaseOneTestList = new LinkedList<>();
        this.phaseTwoTestList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor, ParallelExecutor parallelExecutor, List<TlsProbe> phaseOneTestList, List<TlsProbe> phaseTwoTestList, List<AfterProbe> afterList) {
        this.executor = executor;
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.phaseOneTestList = phaseOneTestList;
        this.phaseTwoTestList = phaseTwoTestList;
        this.afterList = afterList;
        closeAfterFinish = false;
        closeAfterFinishParallel = false;
    }

    private void fillDefaultProbeLists() {
        phaseOneTestList.add(new CommonBugProbe(config, parallelExecutor));
        phaseOneTestList.add(new SniProbe(config, parallelExecutor));
        phaseOneTestList.add(new CompressionsProbe(config, parallelExecutor));
        phaseOneTestList.add(new NamedCurvesProbe(config, parallelExecutor));
        phaseOneTestList.add(new CertificateProbe(config, parallelExecutor));
        phaseOneTestList.add(new ProtocolVersionProbe(config, parallelExecutor));
        phaseOneTestList.add(new CiphersuiteProbe(config, parallelExecutor));
        phaseOneTestList.add(new CiphersuiteOrderProbe(config, parallelExecutor));
        phaseOneTestList.add(new ExtensionProbe(config, parallelExecutor));
        phaseOneTestList.add(new Tls13Probe(config, parallelExecutor));
        phaseOneTestList.add(new TokenbindingProbe(config, parallelExecutor));
        phaseOneTestList.add(new HttpHeaderProbe(config, parallelExecutor));
        phaseTwoTestList.add(new ResumptionProbe(config, parallelExecutor));
        phaseTwoTestList.add(new RenegotiationProbe(config, parallelExecutor));
        phaseTwoTestList.add(new HeartbleedProbe(config, parallelExecutor));
        phaseTwoTestList.add(new PaddingOracleProbe(config, parallelExecutor));
        phaseTwoTestList.add(new BleichenbacherProbe(config, parallelExecutor));
        phaseTwoTestList.add(new PoodleProbe(config, parallelExecutor));
        phaseTwoTestList.add(new TlsPoodleProbe(config, parallelExecutor));
        phaseTwoTestList.add(new Cve20162107Probe(config, parallelExecutor));
        phaseTwoTestList.add(new InvalidCurveProbe(config, parallelExecutor));
        phaseTwoTestList.add(new DrownProbe(config, parallelExecutor));
        phaseTwoTestList.add(new EarlyCcsProbe(config, parallelExecutor));
        phaseTwoTestList.add(new MacProbe(config, parallelExecutor));
        afterList.add(new Sweet32AfterProbe());
        afterList.add(new FreakAfterProbe());
        afterList.add(new LogjamAfterprobe());
    }

    public SiteReport scan() {
        boolean isConnectable = false;
        try {
            if (isConnectable()) {
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if (speaksTls()) {
                    LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                    ScanJob job = new ScanJob(phaseOneTestList, phaseTwoTestList, afterList);
                    SiteReport report = executor.execute(config, job);
                    return report;
                } else {
                    isConnectable = true;
                }
            }
            SiteReport report = new SiteReport(config.getClientDelegate().getHost(), new LinkedList<ProbeType>(), config.isNoColor());
            report.setServerIsAlive(isConnectable);
            report.setSupportsSslTls(false);
            return report;
        } finally {
            closeExecutorsIfNeeded();
        }
    }

    private void closeExecutorsIfNeeded() {
        if (closeAfterFinish) {
            executor.shutdown();
        }
        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    public boolean isConnectable() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }

    private boolean speaksTls() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.speaksTls(tlsConfig);
    }
}
