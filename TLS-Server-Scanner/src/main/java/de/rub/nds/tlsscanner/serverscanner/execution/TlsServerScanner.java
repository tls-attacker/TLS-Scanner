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
import de.rub.nds.tlsscanner.core.constants.QuicAnalyzedProperty;
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
import de.rub.nds.tlsscanner.serverscanner.afterprobe.SessionTicketAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.connectivity.ConnectivityChecker;
import de.rub.nds.tlsscanner.serverscanner.passive.CookieExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DestinationPortExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionIdExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionTicketExtractor;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicAfterHandshakeProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicAntiDosLimitProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicConnectionMigrationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicFragmentationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.quic.QuicRetryPacketProbe;
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
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsServerScanner
        extends Scanner<ServerReport, TlsServerProbe, AfterProbe<ServerReport>, State> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigSelector configSelector;
    private final ParallelExecutor parallelExecutor;
    private final ServerScannerConfig config;
    private final boolean closeAfterFinishParallel;

    /**
     * Constructs a new TlsServerScanner with the specified configuration. Creates a new
     * ParallelExecutor for executing probes.
     *
     * @param config the server scanner configuration to use
     */
    public TlsServerScanner(ServerScannerConfig config) {
        super(config.getExecutorConfig());
        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor =
                ParallelExecutor.create(
                        config.getExecutorConfig().getOverallThreads(),
                        3,
                        new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        setCallbacks();
    }

    /**
     * Constructs a new TlsServerScanner with the specified configuration and parallel executor. The
     * parallel executor will not be shut down when the scanner is closed.
     *
     * @param config the server scanner configuration to use
     * @param parallelExecutor the parallel executor to use for probe execution
     */
    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getExecutorConfig());
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        setCallbacks();
    }

    /**
     * Constructs a new TlsServerScanner with custom probe and after-probe lists. The parallel
     * executor will not be shut down when the scanner is closed.
     *
     * @param config the server scanner configuration to use
     * @param parallelExecutor the parallel executor to use for probe execution
     * @param probeList the list of probes to execute
     * @param afterList the list of after-probes to execute
     */
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
        statsWriter.addExtractor(new SessionTicketExtractor());
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
        registerProbeForExecution(new RawPublicKeyProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ProtocolVersionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CipherSuiteProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DirectRaccoonProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new CipherSuiteOrderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ExtensionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ECPointFormatProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new ResumptionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new RenegotiationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HeartbleedProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new PaddingOracleProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new BleichenbacherProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new InvalidCurveProbe(configSelector, parallelExecutor));
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
        registerProbeForExecution(new EsniProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new TokenbindingProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HttpHeaderProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new HttpFalseStartProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new DrownProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new ConnectionClosingProbe(configSelector, parallelExecutor), false);
        registerProbeForExecution(new PoodleAfterProbe());
        registerProbeForExecution(new SessionTicketProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new SessionTicketManipulationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new SessionTicketPaddingOracleProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new SessionTicketCollectingProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new SessionTicketAfterProbe(configSelector));
        // QUIC-specific
        registerProbeForExecution(new QuicVersionProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new QuicTransportParameterProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicTls12HandshakeProbe(configSelector, parallelExecutor));
        registerProbeForExecution(
                new QuicConnectionMigrationProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicRetryPacketProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicAfterHandshakeProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicAntiDosLimitProbe(configSelector, parallelExecutor));
        registerProbeForExecution(new QuicFragmentationProbe(configSelector, parallelExecutor));
    }

    @Override
    protected ServerReport getEmptyReport() {
        return new ServerReport(
                config.getClientDelegate().getSniHostname(),
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
        boolean isConnectable = false;
        boolean speaksProtocol = false;
        boolean isHandshaking = false;

        if (isConnectable()) {
            isConnectable = true;
            LOGGER.debug("{} is connectable", config.getClientDelegate().getHost());
            configSelector.findWorkingConfigs();
            report.setConfigProfileIdentifier(configSelector.getConfigProfileIdentifier());
            report.setConfigProfileIdentifierTls13(
                    configSelector.getConfigProfileIdentifierTls13());
            if (configSelector.isSpeaksProtocol()) {
                speaksProtocol = true;
                LOGGER.debug(
                        "{} speaks {}", config.getClientDelegate().getHost(), getProtocolType());
                if (configSelector.isIsHandshaking()) {
                    isHandshaking = true;
                    LOGGER.debug("{} is handshaking", config.getClientDelegate().getHost());
                } else {
                    LOGGER.error("{} is not handshaking", config.getClientDelegate().getHost());
                }
            } else {
                LOGGER.error(
                        "{} does not speak {}",
                        config.getClientDelegate().getHost(),
                        getProtocolType());
            }
        } else {
            LOGGER.error("{} is not connectable", config.getClientDelegate().getHost());
        }

        report.setServerIsAlive(isConnectable);
        report.setSpeaksProtocol(speaksProtocol);
        report.setIsHandshaking(isHandshaking);
        report.putResult(TlsAnalyzedProperty.PROTOCOL_TYPE, getProtocolType());
        report.putResult(QuicAnalyzedProperty.RETRY_REQUIRED, configSelector.isQuicRetryRequired());
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
            return List.of();
        }

        LOGGER.debug("Loading guidelines from files...");
        List<String> guidelineFiles = Arrays.asList("bsi.xml", "nist.xml");
        GuidelineIO guidelineIO;
        try {
            guidelineIO = new GuidelineIO(TlsAnalyzedProperty.class);
        } catch (JAXBException e) {
            LOGGER.error("Unable to initialize JAXB context while reading guidelines", e);
            return null;
        }
        List<Guideline<ServerReport>> guidelines = new ArrayList<>();
        for (String guidelineName : guidelineFiles) {
            try {
                InputStream guideLineStream =
                        TlsServerScanner.class.getResourceAsStream("/guideline/" + guidelineName);
                guidelines.add((Guideline<ServerReport>) guidelineIO.read(guideLineStream));
            } catch (JAXBException | XMLStreamException ex) {
                LOGGER.error("Unable to read guideline {} from file", guidelineName, ex);
                return null;
            }
        }
        return guidelines;
    }

    /**
     * Closes the scanner and shuts down the parallel executor if it was created internally. If the
     * parallel executor was provided externally, it will not be shut down.
     */
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

    /**
     * Tests whether a connection can be established to the target server.
     *
     * @return true if the server is connectable, false otherwise
     */
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
