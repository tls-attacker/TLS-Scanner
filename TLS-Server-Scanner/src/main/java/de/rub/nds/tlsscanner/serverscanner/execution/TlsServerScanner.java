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
import de.rub.nds.tlsscanner.serverscanner.afterprobe.SessionTicketAfterProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.connectivity.ConnectivityChecker;
import de.rub.nds.tlsscanner.serverscanner.passive.CookieExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DestinationPortExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionIdExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionTicketExtractor;
import de.rub.nds.tlsscanner.serverscanner.probe.AlpacaProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.AlpnProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaRequiredProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CcaSupportProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
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
import de.rub.nds.tlsscanner.serverscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RandomnessProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RecordFragmentationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketCollectingProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketManipulationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketPaddingOracleProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SessionTicketProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SignatureAndHashAlgorithmProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SignatureHashAlgorithmOrderProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsFallbackScsvProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsServerProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TokenbindingProbe;
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
    private boolean closeAfterFinishParallel;
    private final String vulns;

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
        this.vulns = config.getVulns();
        fillProbeLists();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getExecutorConfig());
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        this.vulns = config.getVulns();
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
        this.vulns = config.getVulns();
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
        if (vulns == "") {
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
            addProbeToProbeList(
                    new SignatureAndHashAlgorithmProbe(configSelector, parallelExecutor));
            addProbeToProbeList(
                    new SignatureHashAlgorithmOrderProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new TlsFallbackScsvProbe(configSelector, parallelExecutor));
            afterList.add(new Sweet32AfterProbe<>());
            afterList.add(new FreakAfterProbe<>());
            afterList.add(new LogjamAfterProbe<>());
            afterList.add(new ServerRandomnessAfterProbe());
            afterList.add(new EcPublicKeyAfterProbe<>());
            afterList.add(new DhValueAfterProbe());
            afterList.add(new PaddingOracleIdentificationAfterProbe<>());
            afterList.add(new RaccoonAttackAfterProbe());
            afterList.add(new CertificateSignatureAndHashAlgorithmAfterProbe());
            // DTLS-specific
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
            afterList.add(new DtlsRetransmissionAfterProbe<>());
            afterList.add(new DestinationPortAfterProbe());
            // TLS-specific
            addProbeToProbeList(new HelloRetryProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new RecordFragmentationProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new EarlyCcsProbe(configSelector, parallelExecutor));
            // addProbeToProbeList(new MacProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new CcaProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new EsniProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new TokenbindingProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new HttpHeaderProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new HttpFalseStartProbe(configSelector, parallelExecutor));
            addProbeToProbeList(new DrownProbe(configSelector, parallelExecutor));
            addProbeToProbeList(
                    new ConnectionClosingProbe(configSelector, parallelExecutor), false);
            afterList.add(new PoodleAfterProbe());
        } else {
            String[] vulnsList = vulns.split(",");
            for (String v : vulnsList) {
                // System.out.println(v);
                switch (v) {
                    case "CommonBug":
                        addProbeToProbeList(new CommonBugProbe(configSelector, parallelExecutor));
                        break;
                    case "Sni":
                        addProbeToProbeList(new SniProbe(configSelector, parallelExecutor));
                        break;
                    case "Compressions":
                        addProbeToProbeList(
                                new CompressionsProbe(configSelector, parallelExecutor));
                        break;
                    case "NamedGroups":
                        addProbeToProbeList(new NamedGroupsProbe(configSelector, parallelExecutor));
                        break;
                    case "NamedCurvesOrder":
                        addProbeToProbeList(
                                new NamedCurvesOrderProbe(configSelector, parallelExecutor));
                        break;
                    case "Alpn":
                        addProbeToProbeList(new AlpnProbe(configSelector, parallelExecutor));
                        break;
                    case "Alpaca":
                        addProbeToProbeList(new AlpacaProbe(configSelector, parallelExecutor));
                        break;
                    case "Certificate":
                        addProbeToProbeList(new CertificateProbe(configSelector, parallelExecutor));
                        break;
                    case "Ocsp":
                        addProbeToProbeList(new OcspProbe(configSelector, parallelExecutor));
                        break;
                    case "ProtocolVersion":
                        addProbeToProbeList(
                                new ProtocolVersionProbe(configSelector, parallelExecutor));
                        break;
                    case "CipherSuite":
                        addProbeToProbeList(new CipherSuiteProbe(configSelector, parallelExecutor));
                        break;
                    case "DirectRaccoon":
                        addProbeToProbeList(
                                new DirectRaccoonProbe(configSelector, parallelExecutor));
                        break;
                    case "CipherSuiteOrder":
                        addProbeToProbeList(
                                new CipherSuiteOrderProbe(configSelector, parallelExecutor));
                        break;
                    case "Extension":
                        addProbeToProbeList(new ExtensionProbe(configSelector, parallelExecutor));
                        break;
                    case "Tokenbinding":
                        addProbeToProbeList(
                                new TokenbindingProbe(configSelector, parallelExecutor));
                        break;
                    case "HttpHeader":
                        addProbeToProbeList(new HttpHeaderProbe(configSelector, parallelExecutor));
                        break;
                    case "HttpFalseStart":
                        addProbeToProbeList(
                                new HttpFalseStartProbe(configSelector, parallelExecutor));
                        break;
                    case "ECPointFormat":
                        addProbeToProbeList(
                                new ECPointFormatProbe(configSelector, parallelExecutor));
                        break;
                    case "Resumption":
                        addProbeToProbeList(new ResumptionProbe(configSelector, parallelExecutor));
                        break;
                    case "Renegotiation":
                        addProbeToProbeList(
                                new RenegotiationProbe(configSelector, parallelExecutor));
                        break;
                    case "SessionTicketZeroKey":
                        addProbeToProbeList(
                                new SessionTicketZeroKeyProbe(configSelector, parallelExecutor));
                        break;
                    case "Heartbleed":
                        addProbeToProbeList(new HeartbleedProbe(configSelector, parallelExecutor));
                        break;
                    case "PaddingOracle":
                        addProbeToProbeList(
                                new PaddingOracleProbe(configSelector, parallelExecutor));
                        break;
                    case "Bleichenbacher":
                        addProbeToProbeList(
                                new BleichenbacherProbe(configSelector, parallelExecutor));
                        break;
                    case "TlsPoodle":
                        afterList.add(new PoodleAfterProbe());
                        break;
                    case "InvalidCurve":
                        addProbeToProbeList(
                                new InvalidCurveProbe(configSelector, parallelExecutor));
                        break;
                    case "Drown":
                        addProbeToProbeList(new DrownProbe(configSelector, parallelExecutor));
                        break;
                    case "EarlyCcs":
                        addProbeToProbeList(new EarlyCcsProbe(configSelector, parallelExecutor));
                        break;
                    case "Mac":
                        addProbeToProbeList(new MacProbe(configSelector, parallelExecutor));
                        break;
                    case "CcaSupport":
                        addProbeToProbeList(new CcaSupportProbe(configSelector, parallelExecutor));
                        break;
                    case "CcaRequired":
                        addProbeToProbeList(new CcaRequiredProbe(configSelector, parallelExecutor));
                        break;
                    case "Cca":
                        addProbeToProbeList(new CcaProbe(configSelector, parallelExecutor));
                        break;
                    case "Esni":
                        addProbeToProbeList(new EsniProbe(configSelector, parallelExecutor));
                        break;
                    case "CertificateTransparency":
                        addProbeToProbeList(
                                new CertificateTransparencyProbe(configSelector, parallelExecutor));
                        break;
                    case "RecordFragmentation":
                        addProbeToProbeList(
                                new RecordFragmentationProbe(configSelector, parallelExecutor));
                        break;
                    case "HelloRetry":
                        addProbeToProbeList(new HelloRetryProbe(configSelector, parallelExecutor));
                        break;
                    case "Sweet32After":
                        afterList.add(new Sweet32AfterProbe<>());
                        break;
                    case "PoodleAfter":
                        afterList.add(new PoodleAfterProbe());
                        break;
                    case "FreakAfter":
                        afterList.add(new FreakAfterProbe<>());
                        break;
                    case "LogjamAfter":
                        afterList.add(new LogjamAfterProbe<>());
                        break;
                    case "ServerRandomnessAfter":
                        afterList.add(new ServerRandomnessAfterProbe());
                        break;
                    case "EcPublicKeyAfter":
                        afterList.add(new EcPublicKeyAfterProbe<>());
                        break;
                    case "DhValueAfter":
                        afterList.add(new DhValueAfterProbe());
                        break;
                    case "PaddingOracleIdentificationAfter":
                        afterList.add(new PaddingOracleIdentificationAfterProbe<>());
                        break;
                    case "RaccoonAttackAfter":
                        afterList.add(new RaccoonAttackAfterProbe());
                        break;
                    default:
                        LOGGER.warn("Unkown vuln type: " + v);
                }
            }
        }
        // Init StatsWriter
        setDefaultProbeWriter();
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
                    LOGGER.debug(config.getClientDelegate().getHost() + " is handshaking");
                }
            }
        }

        report.setServerIsAlive(isConnectable);
        report.setSpeaksProtocol(speaksProtocol);
        report.setIsHandshaking(isHandshaking);
        report.putResult(TlsAnalyzedProperty.PROTOCOL_TYPE, getProtocolType());
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

    @Override
    public void close() {
        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    private ProtocolType getProtocolType() {
        if (config.getDtlsDelegate().isDTLS()) {
            return ProtocolType.DTLS;
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
