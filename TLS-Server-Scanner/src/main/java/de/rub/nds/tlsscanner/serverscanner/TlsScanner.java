/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner;

import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProtocolType;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.rating.ScoreReport;
import de.rub.nds.tlsscanner.serverscanner.rating.SiteReportRater;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DestinationPortAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DhValueAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DtlsRetransmissionAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.LogjamAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.PoodleAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.RaccoonAttackAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.RandomnessAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private boolean closeAfterFinishParallel;
    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;
    private final List<ProbeType> probesToExecute;

    public TlsScanner(ScannerConfig config) {

        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3,
            new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
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
        if (config.getAdditionalRandomnessHandshakes() > 0) {
            addProbeToProbeList(new RandomnessProbe(config, parallelExecutor));
        }
        probeList.add(new AlpnProbe(config, parallelExecutor));
        probeList.add(new AlpacaProbe(config, parallelExecutor));
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
        probeList.add(new SignatureHashAlgorithmOrderProbe(config, parallelExecutor));
        probeList.add(new ExtensionProbe(config, parallelExecutor));
        probeList.add(new ECPointFormatProbe(config, parallelExecutor));
        probeList.add(new ResumptionProbe(config, parallelExecutor));
        probeList.add(new RenegotiationProbe(config, parallelExecutor));
        probeList.add(new SessionTicketZeroKeyProbe(config, parallelExecutor));
        probeList.add(new HeartbleedProbe(config, parallelExecutor));
        probeList.add(new PaddingOracleProbe(config, parallelExecutor));
        probeList.add(new BleichenbacherProbe(config, parallelExecutor));
        probeList.add(new InvalidCurveProbe(config, parallelExecutor));
        probeList.add(new CertificateTransparencyProbe(config, parallelExecutor));
        afterList.add(new Sweet32AfterProbe());
        afterList.add(new FreakAfterProbe());
        afterList.add(new LogjamAfterProbe());
        afterList.add(new RandomnessAfterProbe());
        afterList.add(new EcPublicKeyAfterProbe());
        afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
        afterList.add(new RaccoonAttackAfterProbe());
        if (config.getDtlsDelegate().isDTLS()) {
            probeList.add(new DtlsFeaturesProbe(config, parallelExecutor));
            probeList.add(new DtlsHelloVerifyRequestProbe(config, parallelExecutor));
            probeList.add(new DtlsBugsProbe(config, parallelExecutor));
            probeList.add(new DtlsMessageSequenceProbe(config, parallelExecutor));
            probeList.add(new DtlsRetransmissionsProbe(config, parallelExecutor));
            afterList.add(new DtlsRetransmissionAfterProbe());
            afterList.add(new DestinationPortAfterProbe());
        } else {
            probeList.add(new HelloRetryProbe(config, parallelExecutor));
            probeList.add(new RecordFragmentationProbe(config, parallelExecutor));
            probeList.add(new TlsPoodleProbe(config, parallelExecutor));
            probeList.add(new EarlyCcsProbe(config, parallelExecutor));
            // probeList.add(new MacProbe(config, parallelExecutor));
            probeList.add(new CcaSupportProbe(config, parallelExecutor));
            probeList.add(new CcaRequiredProbe(config, parallelExecutor));
            probeList.add(new CcaProbe(config, parallelExecutor));
            probeList.add(new EsniProbe(config, parallelExecutor));
            probeList.add(new TokenbindingProbe(config, parallelExecutor));
            if (config.getApplicationProtocol() == ApplicationProtocol.HTTP
                || config.getApplicationProtocol() == ApplicationProtocol.UNKNOWN) {
                addProbeToProbeList(new HttpHeaderProbe(config, parallelExecutor));
            }
            probeList.add(new HttpFalseStartProbe(config, parallelExecutor));
            probeList.add(new DrownProbe(config, parallelExecutor));
            afterList.add(new PoodleAfterProbe());
        }
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
        boolean speacksProtocol = false;
        ProtocolType protocolType = config.getDtlsDelegate().isDTLS() ? ProtocolType.DTLS : ProtocolType.TLS;
        ThreadedScanJobExecutor executor = null;
        try {
            if (isConnectable()) {
                isConnectable = true;
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if ((!config.getDtlsDelegate().isDTLS()
                    && config.getStarttlsDelegate().getStarttlsType() == StarttlsType.NONE && speaksTls())
                    || (!config.getDtlsDelegate().isDTLS()
                        && config.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE && speaksStartTls())
                    || config.getDtlsDelegate().isDTLS() && speaksDtls()) {
                    speacksProtocol = true;
                    LOGGER.debug(config.getClientDelegate().getHost() + " speaks " + protocolType.getName());

                    ScanJob job = new ScanJob(probeList, afterList);
                    executor = new ThreadedScanJobExecutor(config, job, config.getParallelProbes(),
                        config.getClientDelegate().getHost());

                    long scanStartTime = System.currentTimeMillis();
                    SiteReport siteReport = executor.execute();
                    SiteReportRater rater;
                    try {
                        rater = SiteReportRater.getSiteReportRater();
                        ScoreReport scoreReport = rater.getScoreReport(siteReport.getResultMap());
                        siteReport.setScore(scoreReport.getScore());
                        siteReport.setScoreReport(scoreReport);

                    } catch (JAXBException ex) {
                        LOGGER.error("Could not retrieve scoring results");
                    }
                    long scanEndTime = System.currentTimeMillis();
                    siteReport.setScanStartTime(scanStartTime);
                    siteReport.setScanEndTime(scanEndTime);

                    siteReport.setServerIsAlive(isConnectable);
                    siteReport.setSpeaksProtocol(speacksProtocol);
                    siteReport.setProtocolType(protocolType);
                    return siteReport;
                }
            }
            SiteReport report = new SiteReport(config.getClientDelegate().getExtractedHost(),
                config.getClientDelegate().getExtractedPort());
            report.setServerIsAlive(isConnectable);
            report.setSpeaksProtocol(speacksProtocol);
            report.setProtocolType(protocolType);
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

    private boolean speaksDtls() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.speaksDTls(tlsConfig);
        } catch (Exception e) {
            LOGGER.warn("Could not test if the server speaks DTLS. Probably could not connect.");
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
