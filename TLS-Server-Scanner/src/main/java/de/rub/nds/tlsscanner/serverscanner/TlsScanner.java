/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineChecker;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.rating.ScoreReport;
import de.rub.nds.tlsscanner.serverscanner.rating.SiteReportRater;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.DestinationPortAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.CertificateSignatureAndHashAlgorithmAfterProbe;
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
import de.rub.nds.tlsscanner.serverscanner.scan.ScanJob;
import de.rub.nds.tlsscanner.serverscanner.scan.ThreadedScanJobExecutor;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigSelector configSelector;
    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private boolean closeAfterFinishParallel;
    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;
    private final List<ProbeType> probesToExecute;

    public TlsScanner(ScannerConfig config) {
        this.config = config;
        this.configSelector = new ConfigSelector(config);
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3,
            new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        this.probesToExecute = config.getProbes();
        setCallbacks();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor) {
        this.config = config;
        this.configSelector = new ConfigSelector(config);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = true;
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        this.probesToExecute = config.getProbes();
        setCallbacks();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ParallelExecutor parallelExecutor, List<TlsProbe> probeList,
        List<AfterProbe> afterList) {
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.configSelector = new ConfigSelector(config);
        this.probeList = probeList;
        this.afterList = afterList;
        this.probesToExecute = config.getProbes();
        closeAfterFinishParallel = true;
        setCallbacks();
    }

    private void setCallbacks() {
        if (config.getCallbackDelegate().getBeforeTransportPreInitCallback() != null
            && parallelExecutor.getDefaultBeforeTransportPreInitCallback() == null) {
            parallelExecutor.setDefaultBeforeTransportPreInitCallback(
                config.getCallbackDelegate().getBeforeTransportPreInitCallback());
        }
        if (config.getCallbackDelegate().getBeforeTransportInitCallback() != null
            && parallelExecutor.getDefaultBeforeTransportInitCallback() == null) {
            parallelExecutor
                .setDefaultBeforeTransportInitCallback(config.getCallbackDelegate().getBeforeTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterTransportInitCallback() != null
            && parallelExecutor.getDefaultAfterTransportInitCallback() == null) {
            parallelExecutor
                .setDefaultAfterTransportInitCallback(config.getCallbackDelegate().getAfterTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterExecutionCallback() != null
            && parallelExecutor.getDefaultAfterExecutionCallback() == null) {
            parallelExecutor.setDefaultAfterExecutionCallback(config.getCallbackDelegate().getAfterExecutionCallback());
        }
    }

    private void fillDefaultProbeLists() {
        if (config.getAdditionalRandomnessHandshakes() > 0) {
            addProbeToProbeList(new RandomnessProbe(configSelector, parallelExecutor));
        }
        addProbeToProbeList(new AlpnProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new AlpacaProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CommonBugProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new SniProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CompressionsProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new NamedGroupsProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new NamedCurvesOrderProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CertificateProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new OcspProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new ProtocolVersionProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CipherSuiteProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new DirectRaccoonProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CipherSuiteOrderProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new ExtensionProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new ECPointFormatProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new ResumptionProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new RenegotiationProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new SessionTicketZeroKeyProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new HeartbleedProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new PaddingOracleProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new BleichenbacherProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new InvalidCurveProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CertificateTransparencyProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CcaSupportProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new CcaRequiredProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new SignatureAndHashAlgorithmProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new SignatureHashAlgorithmOrderProbe(configSelector, parallelExecutor));
        addProbeToProbeList(new TlsFallbackScsvProbe(configSelector, parallelExecutor));
        afterList.add(new Sweet32AfterProbe());
        afterList.add(new FreakAfterProbe());
        afterList.add(new LogjamAfterProbe());
        afterList.add(new RandomnessAfterProbe());
        afterList.add(new EcPublicKeyAfterProbe());
        afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
        afterList.add(new RaccoonAttackAfterProbe());
        afterList.add(new CertificateSignatureAndHashAlgorithmAfterProbe());
        if (config.getDtlsDelegate().isDTLS()) {
            addProbeToProbeList(new DtlsFeaturesProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsHelloVerifyRequestProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsBugsProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsMessageSequenceProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsRetransmissionsProbe(configSelector, parallelExecutor));
            afterList.add(new DtlsRetransmissionAfterProbe());
            afterList.add(new DestinationPortAfterProbe());
        } else {
            addProbeToProbeList(new HelloRetryProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new RecordFragmentationProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new TlsPoodleProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new EarlyCcsProbe(configSelector, parallelExecutor));
            // addProbeToProbeList(new MacProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new CcaProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new EsniProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new TokenbindingProbe(configSelector, parallelExecutor));
            if (config.getApplicationProtocol() == ApplicationProtocol.HTTP
                || config.getApplicationProtocol() == ApplicationProtocol.UNKNOWN) {
                addProbeToProbeList(new HttpHeaderProbe(configSelector, parallelExecutor));
                addProbeToProbeList(new HttpFalseStartProbe(configSelector, parallelExecutor));
            }
            addProbeToProbeList(new DrownProbe(configSelector, parallelExecutor));
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
        boolean speaksProtocol = false;
        boolean isHandshaking = false;
        ProtocolType protocolType = getProtocolType();
        ThreadedScanJobExecutor executor = null;
        try {
            SiteReport siteReport = new SiteReport(config.getClientDelegate().getExtractedHost(),
                config.getClientDelegate().getExtractedPort());
            if (isConnectable()) {
                isConnectable = true;
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if (speaksProtocol(protocolType)) {
                    speaksProtocol = true;
                    LOGGER.debug(config.getClientDelegate().getHost() + " speaks " + protocolType.getName());
                    if (configSelector.init()) {
                        isHandshaking = true;
                        LOGGER.debug(config.getClientDelegate().getHost() + " is handshaking");

                        ScanJob job = new ScanJob(probeList, afterList);
                        executor = new ThreadedScanJobExecutor(config, job, config.getParallelProbes(),
                            config.getClientDelegate().getHost());
                        long scanStartTime = System.currentTimeMillis();
                        siteReport = executor.execute();
                        SiteReportRater rater;
                        try {
                            rater = SiteReportRater.getSiteReportRater();
                            ScoreReport scoreReport = rater.getScoreReport(siteReport.getResultMap());
                            siteReport.setScore(scoreReport.getScore());
                            siteReport.setScoreReport(scoreReport);
                        } catch (JAXBException ex) {
                            LOGGER.error("Could not retrieve scoring results");
                        }
                        if (protocolType != ProtocolType.DTLS) {
                            executeGuidelineEvaluation(siteReport);
                        }
                        long scanEndTime = System.currentTimeMillis();
                        siteReport.setScanStartTime(scanStartTime);
                        siteReport.setScanEndTime(scanEndTime);
                    }
                }
            }
            siteReport.setServerIsAlive(isConnectable);
            siteReport.setSpeaksProtocol(speaksProtocol);
            siteReport.setIsHandshaking(isHandshaking);
            siteReport.setProtocolType(protocolType);
            return siteReport;
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
            closeParallelExecutorIfNeeded();
        }
    }

    private void executeGuidelineEvaluation(SiteReport report) {
        LOGGER.debug("Evaluating guidelines...");
        for (Guideline guideline : GuidelineIO.readGuidelines(GuidelineIO.GUIDELINES)) {
            LOGGER.debug("Evaluating guideline {} ...", guideline.getName());
            GuidelineChecker checker = new GuidelineChecker(guideline);
            checker.fillReport(report);
        }
        LOGGER.debug("Finished evaluating guidelines");
    }

    private void closeParallelExecutorIfNeeded() {

        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    private ProtocolType getProtocolType() {
        if (config.getDtlsDelegate().isDTLS()) {
            return ProtocolType.DTLS;
        } else if (config.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE) {
            return ProtocolType.STARTTLS;
        } else {
            return ProtocolType.TLS;
        }
    }

    public boolean isConnectable() {
        try {
            // TODO: change to config selector?
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.isConnectable();
        } catch (Exception e) {
            LOGGER.warn("Could not test if we can connect to the server", e);
            return false;
        }
    }

    private boolean speaksProtocol(ProtocolType type) {
        try {
            // TODO: change to config selector?
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            switch (type) {
                case TLS:
                    return checker.speaksTls(tlsConfig);
                case DTLS:
                    return checker.speaksDtls(tlsConfig);
                case STARTTLS:
                    return checker.speaksStartTls(tlsConfig);
                default:
                    return false;
            }
        } catch (Exception e) {
            LOGGER.warn("Could not test if the server speaks " + type.getName() + ". Probably could not connect.");
            return false;
        }
    }

    public void setCloseAfterFinishParallel(boolean closeAfterFinishParallel) {
        this.closeAfterFinishParallel = closeAfterFinishParallel;
    }

    public boolean isCloseAfterFinishParallel() {
        return closeAfterFinishParallel;
    }
}
