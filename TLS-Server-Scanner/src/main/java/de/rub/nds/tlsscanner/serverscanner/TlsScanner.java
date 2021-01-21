/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaRequiredProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaSupportProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteOrderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CompressionsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DirectRaccoonProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DrownProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ECPointFormatProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.EarlyCcsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.EsniProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HttpFalseStartProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HttpHeaderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.OcspProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketZeroKeyProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsPoodleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TokenbindingProbe;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DhValueAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.EvaluateRandomnessAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.LogjamAfterProbe;
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
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private boolean closeAfterFinishParallel;
    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;

    public TlsScanner(ScannerConfig config) {

        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor =
            new ParallelExecutor(config.getOverallThreads(), 3, new NamedThreadFactory(config.getClientDelegate()
                .getHost() + "-Worker"));
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor) {
        this.config = config;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = true;
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor, List<TlsProbe> probeList,
        List<AfterProbe> afterList) {
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.probeList = probeList;
        this.afterList = afterList;
        closeAfterFinishParallel = true;
    }

    private void fillDefaultProbeLists() {
        probeList.add(new CommonBugProbe(config, parallelExecutor));
        probeList.add(new SniProbe(config, parallelExecutor));
        probeList.add(new CompressionsProbe(config, parallelExecutor));
        probeList.add(new NamedCurvesProbe(config, parallelExecutor));
        probeList.add(new CertificateProbe(config, parallelExecutor));
        probeList.add(new OcspProbe(config, parallelExecutor));
        probeList.add(new ProtocolVersionProbe(config, parallelExecutor));
        probeList.add(new CipherSuiteProbe(config, parallelExecutor));
        probeList.add(new DirectRaccoonProbe(config, parallelExecutor));
        probeList.add(new CipherSuiteOrderProbe(config, parallelExecutor));
        probeList.add(new ExtensionProbe(config, parallelExecutor));
        probeList.add(new TokenbindingProbe(config, parallelExecutor));
        probeList.add(new HttpHeaderProbe(config, parallelExecutor));
        probeList.add(new HttpFalseStartProbe(config, parallelExecutor));
        probeList.add(new ECPointFormatProbe(config, parallelExecutor));
        probeList.add(new ResumptionProbe(config, parallelExecutor));
        probeList.add(new RenegotiationProbe(config, parallelExecutor));
        probeList.add(new SessionTicketZeroKeyProbe(config, parallelExecutor));
        probeList.add(new HeartbleedProbe(config, parallelExecutor));
        probeList.add(new PaddingOracleProbe(config, parallelExecutor));
        probeList.add(new BleichenbacherProbe(config, parallelExecutor));
        probeList.add(new TlsPoodleProbe(config, parallelExecutor));
        probeList.add(new InvalidCurveProbe(config, parallelExecutor));
        probeList.add(new DrownProbe(config, parallelExecutor));
        probeList.add(new EarlyCcsProbe(config, parallelExecutor));
        // probeList.add(new MacProbe(config, parallelExecutor));
        probeList.add(new CcaSupportProbe(config, parallelExecutor));
        probeList.add(new CcaRequiredProbe(config, parallelExecutor));
        probeList.add(new CcaProbe(config, parallelExecutor));
        probeList.add(new EsniProbe(config, parallelExecutor));
        probeList.add(new CertificateTransparencyProbe(config, parallelExecutor));
        afterList.add(new Sweet32AfterProbe());
        afterList.add(new PoodleAfterProbe());
        afterList.add(new FreakAfterProbe());
        afterList.add(new LogjamAfterProbe());
        afterList.add(new EvaluateRandomnessAfterProbe());
        afterList.add(new EcPublicKeyAfterProbe());
        afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
        afterList.add(new RaccoonAttackAfterProbe());
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
                    executor =
                        new ThreadedScanJobExecutor(config, job, config.getParallelProbes(), config.getClientDelegate()
                            .getHost());
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
        } catch (Exception e) {
            LOGGER.warn("Could not test if we can connect to the server", e);
            return false;
        }
    }

    private boolean speaksTls() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.speaksTls(tlsConfig);
        } catch (Exception e) {
            LOGGER.warn("Could not test if the server speaks TLS. Probably could not connect.");
            LOGGER.debug(e);
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
