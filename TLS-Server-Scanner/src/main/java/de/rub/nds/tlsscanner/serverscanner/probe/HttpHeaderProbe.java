/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.requirements.ProbeRequirement;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpHeaderProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<HttpsHeader> headerList;
    private TestResult speaksHttps;
    private TestResult supportsHsts = TestResults.FALSE;
    private Long hstsMaxAge;
    private Integer hpkpMaxAge;
    private TestResult supportsHstsPreloading = TestResults.FALSE;
    private TestResult supportsHpkp = TestResults.FALSE;
    private TestResult supportsHpkpReportOnly = TestResults.FALSE;
    private TestResult vulnerableBreach = TestResults.FALSE;

    public HttpHeaderProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_HEADER, scannerConfig);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_HSTS);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_HPKP);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING);
        super.properties.add(TlsAnalyzedProperty.VULNERABLE_TO_BREACH);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setHttpsParsingEnabled(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HTTPS);
        tlsConfig.setStopActionsAfterIOException(true);
        // Don't send extensions if we are in SSLv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);

        List<NamedGroup> namedGroups = NamedGroup.getImplemented();
        namedGroups.remove(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new SendAction(new HttpsRequestMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new HttpsResponseMessage()));
        State state = new State(tlsConfig, trace);
        executeState(state);
        ReceivingAction action = trace.getLastReceivingAction();
        HttpsResponseMessage responseMessage = null;
        if (action.getReceivedMessages() != null) {
            for (ProtocolMessage message : action.getReceivedMessages()) {
                if (message instanceof HttpsResponseMessage) {
                    responseMessage = (HttpsResponseMessage) message;
                    break;
                }
            }
        }
        boolean speaksHttps = responseMessage != null;
        if (speaksHttps)
            this.headerList = responseMessage.getHeader();
        else
            this.headerList = new LinkedList<>();
        this.speaksHttps = speaksHttps == true ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public HttpHeaderProbe getCouldNotExecuteResult() {
        this.speaksHttps = TestResults.COULD_NOT_TEST;
        this.headerList = null;
        return this;
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.setPropertyReportValue(TlsAnalyzedProperty.SUPPORTS_HTTPS, this.speaksHttps);
        report.setHeaderList(this.headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        if (this.headerList != null) {
            for (HttpsHeader header : this.headerList) {
                if (header.getHeaderName().getValue().equals("Strict-Transport-Security")) {
                    this.supportsHsts = TestResults.TRUE;
                    boolean preload = false;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("preload"))
                            preload = true;
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    this.hstsMaxAge = Long.parseLong(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HSTS was not parseable", e);
                                }
                            }
                        }
                    }
                    this.supportsHstsPreloading = preload == true ? TestResults.TRUE : TestResults.FALSE;
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins")) {
                    this.supportsHpkp = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    this.hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HPKP was not parseable", e);
                                }
                            }
                        }
                        try {
                            String[] pinString = value.split("=");
                            HpkpPin pin =
                                new HpkpPin(pinString[0], Base64.getDecoder().decode(pinString[1].replace("\"", "")));
                            pinList.add(pin);
                        } catch (Exception e) {
                            LOGGER.warn("HPKP was not parseable", e);
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins-Report-Only")) {
                    this.supportsHpkpReportOnly = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    this.hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HPKP was not parseable", e);
                                }
                            }
                        }
                        if (value.trim().startsWith("pin-")) {
                            try {
                                String[] pinString = value.split("=");
                                HpkpPin pin = new HpkpPin(pinString[0],
                                    Base64.getDecoder().decode(pinString[1].replace("\"", "")));
                                reportOnlyPinList.add(pin);
                            } catch (Exception e) {
                                LOGGER.warn("HPKP was not parseable", e);
                            }
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Content-Encoding")) {
                    String compressionHeaderValue = header.getHeaderValue().getValue();
                    String[] compressionAlgorithms =
                        { "compress", "deflate", "exi", "gzip", "br", "bzip2", "lzma", "xz" };
                    for (String compression : compressionAlgorithms) {
                        if (compressionHeaderValue.contains(compression))
                            this.vulnerableBreach = TestResults.TRUE;
                    }
                }
            }
        } else {
            this.supportsHsts = TestResults.COULD_NOT_TEST;
            this.supportsHstsPreloading = TestResults.COULD_NOT_TEST;
            this.supportsHpkp = TestResults.COULD_NOT_TEST;
            this.supportsHpkpReportOnly = TestResults.COULD_NOT_TEST;
            this.vulnerableBreach = TestResults.COULD_NOT_TEST;
        }
        report.setHstsMaxAge(this.hstsMaxAge);
        super.setPropertyReportValue(TlsAnalyzedProperty.SUPPORTS_HSTS, this.supportsHsts);
        super.setPropertyReportValue(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, this.supportsHstsPreloading);
        super.setPropertyReportValue(TlsAnalyzedProperty.SUPPORTS_HPKP, this.supportsHpkp);
        super.setPropertyReportValue(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, this.supportsHpkpReportOnly);
        report.setHpkpMaxAge(this.hpkpMaxAge);
        report.setNormalHpkpPins(pinList);
        report.setReportOnlyHpkpPins(reportOnlyPinList);
        super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, this.vulnerableBreach);
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report);
    }
}
