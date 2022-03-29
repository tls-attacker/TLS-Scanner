/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.execution.ScanJob;
import de.rub.nds.scanner.core.execution.ThreadedScanJobExecutor;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.execution.TlsScanner;
import de.rub.nds.tlsscanner.core.passive.RandomExtractor;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.CertificateSignatureAndHashAlgorithmAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.DhValueAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.DtlsRetransmissionAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.FreakAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.LogjamAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.PoodleAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.RaccoonAttackAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.RandomnessAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.ProtocolType;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineChecker;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.passive.CbcIvExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.CookieExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DestinationPortExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DhPublicKeyExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DtlsRetransmissionsExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.EcPublicKeyExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionIdExtractor;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.DestinationPortAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import java.io.IOException;
import java.util.List;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsServerScanner extends TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ServerScannerConfig config;
    private boolean closeAfterFinishParallel;

    public TlsServerScanner(ServerScannerConfig config) {
        super(config.getProbes());
        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3,
            new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));

        setCallbacks();
        fillDefaultProbeLists();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getProbes());
        this.config = config;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = true;
        setCallbacks();
        fillDefaultProbeLists();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor, List<ScannerProbe> probeList,
        List<AfterProbe> afterList) {
        super(config.getProbes());
        this.parallelExecutor = parallelExecutor;
        this.config = config;
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

    @Override
    protected void fillDefaultProbeLists() {
        if (config.getAdditionalRandomnessHandshakes() > 0) {
            addProbeToProbeList(new RandomnessProbe(config, parallelExecutor));
        }
        addProbeToProbeList(new AlpnProbe(config, parallelExecutor));
        addProbeToProbeList(new AlpacaProbe(config, parallelExecutor));
        addProbeToProbeList(new CommonBugProbe(config, parallelExecutor));
        addProbeToProbeList(new SniProbe(config, parallelExecutor));
        addProbeToProbeList(new CompressionsProbe(config, parallelExecutor));
        addProbeToProbeList(new NamedGroupsProbe(config, parallelExecutor));
        addProbeToProbeList(new NamedCurvesOrderProbe(config, parallelExecutor));
        addProbeToProbeList(new CertificateProbe(config, parallelExecutor));
        addProbeToProbeList(new OcspProbe(config, parallelExecutor));
        addProbeToProbeList(new ProtocolVersionProbe(config, parallelExecutor));
        addProbeToProbeList(new CipherSuiteProbe(config, parallelExecutor));
        addProbeToProbeList(new DirectRaccoonProbe(config, parallelExecutor));
        addProbeToProbeList(new CipherSuiteOrderProbe(config, parallelExecutor));
        addProbeToProbeList(new ExtensionProbe(config, parallelExecutor));
        addProbeToProbeList(new ECPointFormatProbe(config, parallelExecutor));
        addProbeToProbeList(new ResumptionProbe(config, parallelExecutor));
        addProbeToProbeList(new RenegotiationProbe(config, parallelExecutor));
        addProbeToProbeList(new SessionTicketZeroKeyProbe(config, parallelExecutor));
        addProbeToProbeList(new HeartbleedProbe(config, parallelExecutor));
        addProbeToProbeList(new PaddingOracleProbe(config, parallelExecutor));
        addProbeToProbeList(new BleichenbacherProbe(config, parallelExecutor));
        addProbeToProbeList(new InvalidCurveProbe(config, parallelExecutor));
        addProbeToProbeList(new CertificateTransparencyProbe(config, parallelExecutor));
        addProbeToProbeList(new CcaSupportProbe(config, parallelExecutor));
        addProbeToProbeList(new CcaRequiredProbe(config, parallelExecutor));
        addProbeToProbeList(new SignatureAndHashAlgorithmProbe(config, parallelExecutor));
        addProbeToProbeList(new SignatureHashAlgorithmOrderProbe(config, parallelExecutor));
        addProbeToProbeList(new TlsFallbackScsvProbe(parallelExecutor, config));
        // Init StatsWriter

        for (ScannerProbe probe : probeList) {
            StatsWriter statsWriter = new StatsWriter();
            statsWriter.addExtractor(new CookieExtractor());
            statsWriter.addExtractor(new RandomExtractor());
            statsWriter.addExtractor(new DhPublicKeyExtractor());
            statsWriter.addExtractor(new EcPublicKeyExtractor());
            statsWriter.addExtractor(new CbcIvExtractor());
            statsWriter.addExtractor(new SessionIdExtractor());
            statsWriter.addExtractor(new DtlsRetransmissionsExtractor());
            statsWriter.addExtractor(new DestinationPortExtractor());
            probe.setWriter(statsWriter);
        }

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
            addProbeToProbeList(new DtlsFeaturesProbe(config, parallelExecutor));
            addProbeToProbeList(new DtlsHelloVerifyRequestProbe(config, parallelExecutor));
            addProbeToProbeList(new DtlsBugsProbe(config, parallelExecutor));
            addProbeToProbeList(new DtlsMessageSequenceProbe(config, parallelExecutor));
            addProbeToProbeList(new DtlsRetransmissionsProbe(config, parallelExecutor));
            afterList.add(new DtlsRetransmissionAfterProbe());
            afterList.add(new DestinationPortAfterProbe());
        } else {
            addProbeToProbeList(new HelloRetryProbe(config, parallelExecutor));
            addProbeToProbeList(new RecordFragmentationProbe(config, parallelExecutor));
            addProbeToProbeList(new EarlyCcsProbe(config, parallelExecutor));
            // addProbeToProbeList(new MacProbe(config, parallelExecutor));
            addProbeToProbeList(new CcaProbe(config, parallelExecutor));
            addProbeToProbeList(new EsniProbe(config, parallelExecutor));
            addProbeToProbeList(new TokenbindingProbe(config, parallelExecutor));
            if (config.getApplicationProtocol() == ApplicationProtocol.HTTP
                || config.getApplicationProtocol() == ApplicationProtocol.UNKNOWN) {
                addProbeToProbeList(new HttpHeaderProbe(config, parallelExecutor));
            }
            addProbeToProbeList(new HttpFalseStartProbe(config, parallelExecutor));
            addProbeToProbeList(new DrownProbe(config, parallelExecutor));
            afterList.add(new PoodleAfterProbe());
        }

    }

    public ServerReport scan() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");

        boolean isConnectable = false;
        boolean speaksProtocol = false;
        ProtocolType protocolType = getProtocolType();
        ThreadedScanJobExecutor<ServerReport> executor = null;
        try {
            ServerReport serverReport = new ServerReport(config.getClientDelegate().getExtractedHost(),
                config.getClientDelegate().getExtractedPort());
            if (isConnectable()) {
                isConnectable = true;
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if (speaksProtocol(protocolType)) {
                    speaksProtocol = true;
                    LOGGER.debug(config.getClientDelegate().getHost() + " speaks " + protocolType.getName());

                    ScanJob job = new ScanJob(probeList, afterList);
                    executor = new ThreadedScanJobExecutor<>(config, job, config.getParallelProbes(),
                        config.getClientDelegate().getHost());
                    long scanStartTime = System.currentTimeMillis();
                    serverReport = executor.execute(serverReport);
                    SiteReportRater rater;
                    try {
                        rater = DefaultRatingLoader.getServerReportRater("en");
                        ScoreReport scoreReport = rater.getScoreReport(serverReport.getResultMap());
                        serverReport.setScore(scoreReport.getScore());
                        serverReport.setScoreReport(scoreReport);

                    } catch (IOException | JAXBException | XMLStreamException ex) {
                        LOGGER.error("Could not retrieve scoring results");
                    }
                    if (protocolType != ProtocolType.DTLS) {
                        executeGuidelineEvaluation(serverReport);
                    }
                    long scanEndTime = System.currentTimeMillis();
                    serverReport.setScanStartTime(scanStartTime);
                    serverReport.setScanEndTime(scanEndTime);
                    return serverReport;
                }
            } else {
                isConnectable = false;
            }
            serverReport.setServerIsAlive(isConnectable);
            serverReport.setSpeaksProtocol(speaksProtocol);
            serverReport.setProtocolType(protocolType);
            return serverReport;
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
            closeParallelExecutorIfNeeded();
        }
    }

    private void executeGuidelineEvaluation(ServerReport report) {
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
