/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.execution.Scanner;
import de.rub.nds.scanner.core.guideline.Guideline;
import de.rub.nds.scanner.core.guideline.GuidelineIO;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.afterprobe.DtlsRetransmissionAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.FreakAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.LogjamAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.core.afterprobe.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
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
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateSignatureCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateValidityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateVersionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtendedKeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmStrengthCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;
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
import de.rub.nds.tlsscanner.serverscanner.probe.TlsServerProbe;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsServerScanner
        extends Scanner<ServerReport, TlsServerProbe, AfterProbe<ServerReport>, State> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigSelector configSelector;
    private final ParallelExecutor parallelExecutor;
    private final ServerScannerConfig config;
    private boolean closeAfterFinishParallel;

    public TlsServerScanner(ServerScannerConfig config) {
        super(config.getExecutorConfig());
        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor =
                new ParallelExecutor(
                        config.getExecutorConfig().getOverallThreads(),
                        3,
                        new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        setCallbacks();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getExecutorConfig());
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        setCallbacks();
    }

    public TlsServerScanner(
            ServerScannerConfig config,
            ParallelExecutor parallelExecutor,
            List<TlsServerProbe> probeList,
            List<AfterProbe<ServerReport>> afterList) {
        super(config.getExecutorConfig(), probeList, afterList);
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        closeAfterFinishParallel = false;
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
    protected StatsWriter<State> getDefaultProbeWriter() {
        StatsWriter<State> statsWriter = new StatsWriter<>();
        statsWriter.addExtractor(new CookieExtractor());
        statsWriter.addExtractor(new RandomExtractor());
        statsWriter.addExtractor(new DhPublicKeyExtractor());
        statsWriter.addExtractor(new EcPublicKeyExtractor());
        statsWriter.addExtractor(new CbcIvExtractor());
        statsWriter.addExtractor(new SessionIdExtractor());
        statsWriter.addExtractor(new DtlsRetransmissionsExtractor());
        statsWriter.addExtractor(new DestinationPortExtractor());
        return statsWriter;
    }

    @Override
    protected void fillProbeLists() {
        if (config.getAdditionalRandomnessHandshakes() > 0) {
            registerProbeForExecution(new RandomnessProbe(configSelector, parallelExecutor));
        }
        registerProbeForExecution(new AlpnProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new AlpacaProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CommonBugProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new SniProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CompressionsProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new NamedGroupsProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new NamedCurvesOrderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CertificateProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new OcspProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ProtocolVersionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CipherSuiteProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DirectRaccoonProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CipherSuiteOrderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ExtensionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ECPointFormatProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ResumptionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new RenegotiationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new SessionTicketZeroKeyProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HeartbleedProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new PaddingOracleProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new BleichenbacherProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new InvalidCurveProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new CertificateTransparencyProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CcaSupportProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CcaRequiredProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new SignatureAndHashAlgorithmProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new SignatureHashAlgorithmOrderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new TlsFallbackScsvProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new Sweet32AfterProbe<>());
        registerProbeForExecution(new FreakAfterProbe<>());
        registerProbeForExecution(new LogjamAfterProbe<>());
        registerProbeForExecution(new ServerRandomnessAfterProbe());
        registerProbeForExecution(new EcPublicKeyAfterProbe<>());
        registerProbeForExecution(new DhValueAfterProbe());
        registerProbeForExecution(new PaddingOracleIdentificationAfterProbe<>());
        registerProbeForExecution(new RaccoonAttackAfterProbe());
        registerProbeForExecution(new CertificateSignatureAndHashAlgorithmAfterProbe());
        // DTLS-specific
        registerProbeForExecution(new DtlsReorderingProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DtlsFragmentationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new DtlsHelloVerifyRequestProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DtlsBugsProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DtlsMessageSequenceProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DtlsRetransmissionsProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new DtlsApplicationFingerprintProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new DtlsIpAddressInCookieProbe(configSelector, parallelExecutor), false);
        registerProbeForExecution(new DtlsRetransmissionAfterProbe<>());
        registerProbeForExecution(new DestinationPortAfterProbe());
        // TLS-specific
        registerProbeForExecution(new HelloRetryProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new RecordFragmentationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new EarlyCcsProbe(configSelector, parallelExecutor));
        // registerProbeForExecution(new MacProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CcaProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new EsniProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new TokenbindingProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HttpHeaderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HttpFalseStartProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DrownProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new ConnectionClosingProbe(configSelector, parallelExecutor), false);
        registerProbeForExecution(new PoodleAfterProbe());
        // QUIC-specific
        registerProbeForExecution(new QuicVersionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new QuicTransportParameterProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicTls12HandshakeProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new QuicConnectionMigrationProbe(configSelector, parallelExecutor));
    }

    @Override
    protected ServerReport getEmptyReport() {
        return new ServerReport(
                config.getClientDelegate().getExtractedHost(),
                config.getClientDelegate().getExtractedPort());
    }

    @Override
    protected void onScanStart() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");
    }

    @Override
    protected boolean checkScanPrerequisites(ServerReport report) {
        report.setProtocolType(getProtocolType());
        boolean isConnectable = false;
        boolean speaksProtocol = false;
        boolean isHandshaking = false;
        boolean quicRetryRequired = false;

        if (isConnectable()) {
            isConnectable = true;
            LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
            configSelector.findWorkingConfigs();
            report.setConfigProfileIdentifier(configSelector.getConfigProfileIdentifier());
            report.setConfigProfileIdentifierTls13(
                    configSelector.getConfigProfileIdentifierTls13());
            if (configSelector.isSpeaksProtocol()) {
                speaksProtocol = true;
                LOGGER.debug(config.getClientDelegate().getHost() + " speaks " + getProtocolType());
                if (configSelector.isIsHandshaking()) {
                    isHandshaking = true;
                    quicRetryRequired = configSelector.isQuicRetryRequired();
                    LOGGER.debug(config.getClientDelegate().getHost() + " is handshaking");
                }
            }
        }

        report.setServerIsAlive(isConnectable);
        report.setSpeaksProtocol(speaksProtocol);
        report.setIsHandshaking(isHandshaking);
        report.setProtocolType(getProtocolType());
        report.setQuicRetryRequired(quicRetryRequired);
        return isConnectable && speaksProtocol && isHandshaking;
    }

    @Override
    protected SiteReportRater getSiteReportRater() {
        try {
            return DefaultRatingLoader.getServerReportRater("en");
        } catch (JAXBException | IOException | XMLStreamException e) {
            LOGGER.error("Failed to load server report rater, continuing without scoring");
            return null;
        }
    }

    @Override
    protected List<Guideline<ServerReport>> getGuidelines() {
        if (getProtocolType() == ProtocolType.DTLS) {
            return null;
        }

        LOGGER.debug("Loading guidelines from files...");
        List<String> guidelineFiles = Arrays.asList("bsi.xml", "nist.xml");
        GuidelineIO<ServerReport> guidelineIO;
        try {
            guidelineIO =
                    new GuidelineIO<>(
                            TlsAnalyzedProperty.class,
                            Set.of(
                                    AnalyzedPropertyGuidelineCheck.class,
                                    CertificateAgilityGuidelineCheck.class,
                                    CertificateCurveGuidelineCheck.class,
                                    CertificateSignatureCheck.class,
                                    CertificateValidityGuidelineCheck.class,
                                    CertificateVersionGuidelineCheck.class,
                                    CipherSuiteGuidelineCheck.class,
                                    ExtendedKeyUsageCertificateCheck.class,
                                    ExtensionGuidelineCheck.class,
                                    HashAlgorithmsGuidelineCheck.class,
                                    HashAlgorithmStrengthCheck.class,
                                    KeySizeCertGuidelineCheck.class,
                                    KeyUsageCertificateCheck.class,
                                    NamedGroupsGuidelineCheck.class,
                                    SignatureAlgorithmsCertificateGuidelineCheck.class,
                                    SignatureAlgorithmsGuidelineCheck.class,
                                    SignatureAndHashAlgorithmsCertificateGuidelineCheck.class,
                                    SignatureAndHashAlgorithmsGuidelineCheck.class));
        } catch (JAXBException e) {
            LOGGER.error("Unable to initialize JAXB context while reading guidelines", e);
            return null;
        }
        List<Guideline<ServerReport>> guidelines = new ArrayList<>();
        for (String guidelineName : guidelineFiles) {
            try {
                InputStream guideLineStream =
                        TlsServerScanner.class.getResourceAsStream("/guideline/" + guidelineName);
                guidelines.add(guidelineIO.read(guideLineStream));
            } catch (JAXBException | XMLStreamException ex) {
                LOGGER.error("Unable to read guideline {} from file", guidelineName, ex);
                return null;
            }
        }
        return guidelines;
    }

    @Override
    public void close() {
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
}
