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
import de.rub.nds.scanner.core.probe.requirements.BaseRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpHeaderProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

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

    public HttpHeaderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_HEADER, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_HSTS, TlsAnalyzedProperty.SUPPORTS_HTTPS,
            TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, TlsAnalyzedProperty.SUPPORTS_HPKP,
            TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, TlsAnalyzedProperty.VULNERABLE_TO_BREACH,
            TlsAnalyzedProperty.LIST_HTTPS_HEADER, TlsAnalyzedProperty.LIST_NORMAL_HPKPPINS,
            TlsAnalyzedProperty.LIST_REPORT_ONLY_HPKPPINS);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setHttpsParsingEnabled(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
        State state = new State(tlsConfig);
        executeState(state);

        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
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
            headerList = responseMessage.getHeader();
        else
            headerList = new LinkedList<>();
        this.speaksHttps = speaksHttps == true ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_HTTPS, speaksHttps);
        put(TlsAnalyzedProperty.LIST_HTTPS_HEADER, headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        if (headerList != null) {
            for (HttpsHeader header : headerList) {
                if (header.getHeaderName().getValue().equals("Strict-Transport-Security")) {
                    supportsHsts = TestResults.TRUE;
                    boolean preload = false;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("preload"))
                            preload = true;
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hstsMaxAge = Long.parseLong(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HSTS was not parseable", e);
                                }
                            }
                        }
                    }
                    supportsHstsPreloading = preload == true ? TestResults.TRUE : TestResults.FALSE;
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins")) {
                    supportsHpkp = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
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
                    supportsHpkpReportOnly = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
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
                            vulnerableBreach = TestResults.TRUE;
                    }
                }
            }
        } else {
            supportsHsts = TestResults.COULD_NOT_TEST;
            supportsHstsPreloading = TestResults.COULD_NOT_TEST;
            supportsHpkp = TestResults.COULD_NOT_TEST;
            supportsHpkpReportOnly = TestResults.COULD_NOT_TEST;
            vulnerableBreach = TestResults.COULD_NOT_TEST;
        }
        report.setHstsMaxAge(hstsMaxAge);
        put(TlsAnalyzedProperty.SUPPORTS_HSTS, supportsHsts);
        put(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, supportsHstsPreloading);
        put(TlsAnalyzedProperty.SUPPORTS_HPKP, supportsHpkp);
        put(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, supportsHpkpReportOnly);
        report.setHpkpMaxAge(hpkpMaxAge);
        put(TlsAnalyzedProperty.LIST_NORMAL_HPKPPINS, pinList);
        put(TlsAnalyzedProperty.LIST_REPORT_ONLY_HPKPPINS, reportOnlyPinList);
        put(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, vulnerableBreach);
    }

    @Override
    protected Requirement getRequirements() {
        return BaseRequirement.NO_REQUIREMENT;
    }
}
