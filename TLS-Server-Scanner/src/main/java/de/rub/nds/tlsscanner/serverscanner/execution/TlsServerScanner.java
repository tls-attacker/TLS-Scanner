/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.afterprobe.DtlsRetransmissionAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.FreakAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.LogjamAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.execution.TlsScanner;
import de.rub.nds.tlsscanner.core.passive.CbcIvExtractor;
import de.rub.nds.tlsscanner.core.passive.DhPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.DtlsRetransmissionsExtractor;
import de.rub.nds.tlsscanner.core.passive.EcPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.RandomExtractor;
import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.CertificateSignatureAndHashAlgorithmAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.DestinationPortAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.DhValueAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.PoodleAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.RaccoonAttackAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.ServerRandomnessAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.connectivity.ConnectivityChecker;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineChecker;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.passive.CookieExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DestinationPortExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionIdExtractor;
import de.rub.nds.tlsscanner.serverscanner.probe.AlpacaProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.AlpnProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaRequiredProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaSupportProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateTransparencyProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteOrderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CompressionsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ConnectionClosingProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DirectRaccoonProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DrownProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsApplicationFingerprintProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsBugsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsFragmentationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsHelloVerifyRequestProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsIpAddressInCookieProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsMessageSequenceProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsReorderingProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsRetransmissionsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ECPointFormatProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.EarlyCcsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.EsniProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HelloRetryProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HttpFalseStartProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.HttpHeaderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.NamedCurvesOrderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.NamedGroupsProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.OcspProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RandomnessProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RecordFragmentationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketZeroKeyProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SignatureAndHashAlgorithmProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SignatureHashAlgorithmOrderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsFallbackScsvProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TokenbindingProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicConnectionMigrationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicTls12HandshakeProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicTransportParameterProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicVersionProbe;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsServerScanner extends TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigSelector configSelector;
    private final ParallelExecutor parallelExecutor;
    private final ServerScannerConfig config;
    private boolean closeAfterFinishParallel;

    public TlsServerScanner(ServerScannerConfig config) {
        super(config.getProbes());
        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor =
                new ParallelExecutor(
                        config.getOverallThreads(),
                        3,
                        new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        setCallbacks();
        fillProbeLists();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getProbes());
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        setCallbacks();
        fillProbeLists();
    }

    public TlsServerScanner(
            ServerScannerConfig config,
            ParallelExecutor parallelExecutor,
            List<ScannerProbe> probeList,
            List<AfterProbe> afterList) {
        super(probeList.stream().map(ScannerProbe::getType).collect(Collectors.toList()));
        this.probeList.addAll(probeList);
        this.afterList.addAll(afterList);
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        closeAfterFinishParallel = false;
        setDefaultProbeWriter();
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
            parallelExecutor.setDefaultBeforeTransportInitCallback(
                    config.getCallbackDelegate().getBeforeTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterTransportInitCallback() != null
                && parallelExecutor.getDefaultAfterTransportInitCallback() == null) {
            parallelExecutor.setDefaultAfterTransportInitCallback(
                    config.getCallbackDelegate().getAfterTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterExecutionCallback() != null
                && parallelExecutor.getDefaultAfterExecutionCallback() == null) {
            parallelExecutor.setDefaultAfterExecutionCallback(
                    config.getCallbackDelegate().getAfterExecutionCallback());
        }
    }

    @Override
    protected void fillProbeLists() {
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
        afterList.add(new ServerRandomnessAfterProbe());
        afterList.add(new EcPublicKeyAfterProbe());
        afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
        afterList.add(new RaccoonAttackAfterProbe());
        afterList.add(new CertificateSignatureAndHashAlgorithmAfterProbe());
        if (config.getDtlsDelegate().isDTLS()) {
            addProbeToProbeList(new DtlsReorderingProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsFragmentationProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsHelloVerifyRequestProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsBugsProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsMessageSequenceProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DtlsRetransmissionsProbe(configSelector, parallelExecutor));
            addProbeToProbeList(
                    new DtlsApplicationFingerprintProbe(configSelector, parallelExecutor));
            addProbeToProbeList(
                    new DtlsIpAddressInCookieProbe(configSelector, parallelExecutor), false);
            afterList.add(new DtlsRetransmissionAfterProbe());
            afterList.add(new DestinationPortAfterProbe());
        } else {
            addProbeToProbeList(new HelloRetryProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new RecordFragmentationProbe(configSelector, parallelExecutor));
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
            addProbeToProbeList(
                    new ConnectionClosingProbe(configSelector, parallelExecutor), false);
            afterList.add(new PoodleAfterProbe());
        }
        if (config.getQuicDelegate().isQuic()) {
            addProbeToProbeList(new QuicVersionProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new QuicTransportParameterProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new QuicTls12HandshakeProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new QuicConnectionMigrationProbe(configSelector, parallelExecutor));
        }
        // Init StatsWriter
        setDefaultProbeWriter();
    }

    private void setDefaultProbeWriter() {
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
    }

    public ServerReport scan() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");

        boolean isConnectable = false;
        boolean speaksProtocol = false;
        boolean isHandshaking = false;
        boolean quicRetryRequired = false;
        ProtocolType protocolType = getProtocolType();
        ThreadedScanJobExecutor<ServerReport> executor = null;
        // TODO Kind of hacky - this extracts the hosts from the client delegate - otherwise its not
        // initialized
        ServerReport serverReport =
                new ServerReport(
                        config.getClientDelegate().getExtractedHost(),
                        config.getClientDelegate().getExtractedPort());

        if (isConnectable()) {
            isConnectable = true;
            LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
            configSelector.findWorkingConfigs();
            serverReport.setConfigProfileIdentifier(configSelector.getConfigProfileIdentifier());
            serverReport.setConfigProfileIdentifierTls13(
                    configSelector.getConfigProfileIdentifierTls13());
            if (configSelector.isSpeaksProtocol()) {
                speaksProtocol = true;
                LOGGER.debug(
                        config.getClientDelegate().getHost() + " speaks " + protocolType.getName());
                if (configSelector.isIsHandshaking()) {
                    isHandshaking = true;
                    quicRetryRequired = configSelector.isQuicRetryRequired();
                    LOGGER.debug(config.getClientDelegate().getHost() + " is handshaking");

                    ScanJob job = new ScanJob(probeList, afterList);
                    executor =
                            new ThreadedScanJobExecutor<>(
                                    config,
                                    job,
                                    config.getParallelProbes(),
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
                }
            }
        }

        serverReport.setServerIsAlive(isConnectable);
        serverReport.setSpeaksProtocol(speaksProtocol);
        serverReport.setIsHandshaking(isHandshaking);
        serverReport.setProtocolType(protocolType);
        serverReport.setQuicRetryRequired(quicRetryRequired);

        if (executor != null) {
            executor.shutdown();
        }
        closeParallelExecutorIfNeeded();

        return serverReport;
    }

    private void executeGuidelineEvaluation(ServerReport report) {
        LOGGER.debug("Evaluating guidelines...");
        List<String> guidelines = Arrays.asList("bsi.xml", "nist.xml");

        for (String guidelineName : guidelines) {
            try {
                InputStream guideLineStream =
                        GuidelineIO.class.getResourceAsStream("/guideline/" + guidelineName);
                Guideline guideline = GuidelineIO.read(guideLineStream);
                LOGGER.debug("Evaluating guideline {} ...", guideline.getName());
                GuidelineChecker checker = new GuidelineChecker(guideline);
                checker.fillReport(report);
            } catch (JAXBException | IOException | XMLStreamException ex) {
                LOGGER.error("Could not read guideline", ex);
            }
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
        } else if (config.getQuicDelegate().isQuic()) {
            return ProtocolType.QUIC;
        } else if (config.getStartTlsDelegate().getStarttlsType() != StarttlsType.NONE) {
            return ProtocolType.STARTTLS;
        } else {
            return ProtocolType.TLS;
        }
    }

    public boolean isConnectable() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker =
                    new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.isConnectable();
        } catch (Exception e) {
            LOGGER.warn("Could not test if we can connect to the server", e);
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
