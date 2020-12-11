/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner;

import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.probe.EsniProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DhValueAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.EvaluateRandomnessAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.LogjamAfterprobe;
import de.rub.nds.tlsscanner.serverscanner.report.after.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.PoodleAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.RaccoonAttackAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
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

    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private boolean closeAfterFinishParallel;
    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;
    private final List<ProbeType> probesToExecute;

    public TlsScanner(ScannerConfig config) {

        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3, new NamedThreadFactory(config
                .getClientDelegate().getHost() + "-Worker"));
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        this.probesToExecute = config.getProbes();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor) {
        this.config = config;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = true;
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        this.probesToExecute = config.getProbes();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor, List<TlsProbe> probeList,
            List<AfterProbe> afterList) {
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.probeList = probeList;
        this.afterList = afterList;
        this.probesToExecute = config.getProbes();
        closeAfterFinishParallel = true;
    }

    private void fillDefaultProbeLists() {
        addProbeToProbeList(new GreaseProbe(config, parallelExecutor));
        addProbeToProbeList(new CommonBugProbe(config, parallelExecutor));
        addProbeToProbeList(new SniProbe(config, parallelExecutor));
        addProbeToProbeList(new CompressionsProbe(config, parallelExecutor));
        addProbeToProbeList(new NamedCurvesProbe(config, parallelExecutor));
        addProbeToProbeList(new CertificateProbe(config, parallelExecutor));
        addProbeToProbeList(new OcspProbe(config, parallelExecutor));
        addProbeToProbeList(new ProtocolVersionProbe(config, parallelExecutor));
        addProbeToProbeList(new CiphersuiteProbe(config, parallelExecutor));
        addProbeToProbeList(new DirectRaccoonProbe(config, parallelExecutor));
        addProbeToProbeList(new CiphersuiteOrderProbe(config, parallelExecutor));
        addProbeToProbeList(new ExtensionProbe(config, parallelExecutor));
        addProbeToProbeList(new TokenbindingProbe(config, parallelExecutor));
        addProbeToProbeList(new HttpHeaderProbe(config, parallelExecutor));
        addProbeToProbeList(new HttpFalseStartProbe(config, parallelExecutor));
        addProbeToProbeList(new ECPointFormatProbe(config, parallelExecutor));
        addProbeToProbeList(new ResumptionProbe(config, parallelExecutor));
        addProbeToProbeList(new RenegotiationProbe(config, parallelExecutor));
        addProbeToProbeList(new SessionTicketZeroKeyProbe(config, parallelExecutor));
        addProbeToProbeList(new HeartbleedProbe(config, parallelExecutor));
        addProbeToProbeList(new PaddingOracleProbe(config, parallelExecutor));
        addProbeToProbeList(new BleichenbacherProbe(config, parallelExecutor));
        addProbeToProbeList(new TlsPoodleProbe(config, parallelExecutor));
        addProbeToProbeList(new InvalidCurveProbe(config, parallelExecutor));
        addProbeToProbeList(new DrownProbe(config, parallelExecutor));
        addProbeToProbeList(new EarlyCcsProbe(config, parallelExecutor));
        addProbeToProbeList(new RecordFragmentationProbe(config, parallelExecutor));
        // addProbeToProbeList(new MacProbe(config, parallelExecutor));
        addProbeToProbeList(new CcaSupportProbe(config, parallelExecutor));
        addProbeToProbeList(new CcaRequiredProbe(config, parallelExecutor));
        addProbeToProbeList(new CcaProbe(config, parallelExecutor));
        addProbeToProbeList(new EsniProbe(config, parallelExecutor));
        afterList.add(new Sweet32AfterProbe());
        afterList.add(new PoodleAfterProbe());
        afterList.add(new FreakAfterProbe());
        afterList.add(new LogjamAfterprobe());
        afterList.add(new EvaluateRandomnessAfterProbe());
        afterList.add(new EcPublicKeyAfterProbe());
        afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
        afterList.add(new RaccoonAttackAfterProbe());
    }

    private void addProbeToProbeList(TlsProbe probe) {
        if (probesToExecute == null || probesToExecute.contains(probe.getType())) {
            probeList.add(probe);
        }
    }

    public SiteReport scan() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");

        boolean isConnectable = false;
        ThreadedScanJobExecutor executor = null;
        try {
            if (isConnectable()) {
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if ((config.getStarttlsDelegate().getStarttlsType() == StarttlsType.NONE && speaksTls())
                        || (config.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE && speaksStartTls())) {
                    LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                    ScanJob job = new ScanJob(probeList, afterList);
                    executor = new ThreadedScanJobExecutor(config, job, config.getParallelProbes(), config
                            .getClientDelegate().getHost());
                    SiteReport report = executor.execute();
                    return report;
                } else {
                    isConnectable = true;
                }
            }
            SiteReport report = new SiteReport(config.getClientDelegate().getHost());
            report.setServerIsAlive(isConnectable);
            report.setSupportsSslTls(false);
            return report;
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
            closeParallelExecutorIfNeeded();
        }
    }

    private void closeParallelExecutorIfNeeded() {

        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    public boolean isConnectable() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.isConnectable();
        } catch (Exception E) {
            LOGGER.warn("Could not test if we can connect to the server", E);
            return false;
        }
    }

    private boolean speaksTls() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.speaksTls(tlsConfig);
        } catch (Exception E) {
            LOGGER.warn("Could not test if the server speaks TLS. Probably could not connect.");
            LOGGER.debug(E);
            return false;
        }
    }

    private boolean speaksStartTls() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.speaksStartTls(tlsConfig);
    }

    public void setCloseAfterFinishParallel(boolean closeAfterFinishParallel) {
        this.closeAfterFinishParallel = closeAfterFinishParallel;
    }

    public boolean isCloseAfterFinishParallel() {
        return closeAfterFinishParallel;
    }
}
