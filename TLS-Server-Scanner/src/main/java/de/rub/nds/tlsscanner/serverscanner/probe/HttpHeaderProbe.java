/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

public class HttpHeaderProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<HttpHeader> headerList;
    private TestResult speaksHttps = TestResults.COULD_NOT_TEST;
    private TestResult supportsHsts = TestResults.COULD_NOT_TEST;
    private Long hstsMaxAge;
    private Integer hpkpMaxAge;
    private TestResult hstsIncludesSubdomains = TestResults.FALSE;
    private TestResult hpkpIncludesSubdomains = TestResults.FALSE;
    private TestResult supportsHstsPreloading = TestResults.FALSE;
    private TestResult hstsNotParseable = TestResults.FALSE;
    private TestResult hpkpNotParseable = TestResults.FALSE;
    private TestResult supportsHpkp = TestResults.FALSE;
    private TestResult supportsHpkpReportOnly = TestResults.FALSE;
    private TestResult vulnerableBreach = TestResults.FALSE;

    public HttpHeaderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_HEADER, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_HSTS,
                TlsAnalyzedProperty.SUPPORTS_HTTPS,
                TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING,
                TlsAnalyzedProperty.SUPPORTS_HPKP,
                TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING,
                TlsAnalyzedProperty.VULNERABLE_TO_BREACH,
                TlsAnalyzedProperty.HTTPS_HEADER,
                TlsAnalyzedProperty.NORMAL_HPKP_PINS,
                TlsAnalyzedProperty.HSTS_INCLUDES_SUBDOMAINS,
                TlsAnalyzedProperty.HPKP_INCLUDES_SUBDOMAINS,
                TlsAnalyzedProperty.HSTS_NOT_PARSEABLE,
                TlsAnalyzedProperty.HPKP_NOT_PARSEABLE,
                TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
        State state = new State(tlsConfig);
        executeState(state);

        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        HttpResponseMessage responseMessage = null;
        if (action.getReceivedHttpMessages() != null) {
            for (HttpMessage httpMessage : action.getReceivedHttpMessages()) {
                if (httpMessage instanceof HttpResponseMessage) {
                    responseMessage = (HttpResponseMessage) httpMessage;
                    break;
                }
            }
        }
        if (responseMessage != null) {
            headerList = responseMessage.getHeader();
        } else {
            headerList = new LinkedList<>();
        }
        this.speaksHttps = responseMessage != null ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_HTTPS, speaksHttps);
        put(TlsAnalyzedProperty.HTTPS_HEADER, headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        supportsHsts = TestResults.FALSE;
        if (headerList != null) {
            for (HttpHeader header : headerList) {
                if (header.getHeaderName()
                        .getValue()
                        .toLowerCase()
                        .equals("strict-transport-security")) {
                    supportsHsts = TestResults.TRUE;
                    boolean preload = false;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("preload")) {
                            preload = true;
                        }
                        if (value.trim().startsWith("includeSubDomains")) {
                            hstsIncludesSubdomains = TestResults.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hstsMaxAge = Long.parseLong(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HSTS was not parseable", e);
                                    hstsNotParseable = TestResults.TRUE;
                                }
                            } else {
                                hstsNotParseable = TestResults.FALSE;
                            }
                        }
                    }
                    supportsHstsPreloading = preload == true ? TestResults.TRUE : TestResults.FALSE;
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins")) {
                    supportsHpkp = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("includeSubDomains")) {
                            hpkpIncludesSubdomains = TestResults.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HPKP was not parseable", e);
                                    hpkpNotParseable = TestResults.TRUE;
                                }
                            } else {
                                hpkpNotParseable = TestResults.FALSE;
                            }
                        }
                        try {
                            String[] pinString = value.split("=");
                            HpkpPin pin =
                                    new HpkpPin(
                                            pinString[0],
                                            Base64.getDecoder()
                                                    .decode(pinString[1].replace("\"", "")));
                            pinList.add(pin);
                        } catch (Exception e) {
                            LOGGER.warn("HPKP was not parseable", e);
                            hpkpNotParseable = TestResults.TRUE;
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins-Report-Only")) {
                    supportsHpkpReportOnly = TestResults.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("includeSubDomains")) {
                            hpkpIncludesSubdomains = TestResults.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception e) {
                                    LOGGER.warn("HPKP was not parseable", e);
                                    hpkpNotParseable = TestResults.TRUE;
                                }
                            } else {
                                hpkpNotParseable = TestResults.FALSE;
                            }
                        }
                        if (value.trim().startsWith("pin-")) {
                            try {
                                String[] pinString = value.split("=");
                                HpkpPin pin =
                                        new HpkpPin(
                                                pinString[0],
                                                Base64.getDecoder()
                                                        .decode(pinString[1].replace("\"", "")));
                                reportOnlyPinList.add(pin);
                            } catch (Exception e) {
                                LOGGER.warn("HPKP was not parseable", e);
                                hpkpNotParseable = TestResults.TRUE;
                            }
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Content-Encoding")) {
                    String compressionHeaderValue = header.getHeaderValue().getValue();
                    String[] compressionAlgorithms = {
                        "compress", "deflate", "exi", "gzip", "br", "bzip2", "lzma", "xz"
                    };
                    for (String compression : compressionAlgorithms) {
                        if (compressionHeaderValue.contains(compression)) {
                            vulnerableBreach = TestResults.TRUE;
                        }
                    }
                }
            }
            put(TlsAnalyzedProperty.SUPPORTS_HSTS, supportsHsts);
            put(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, supportsHstsPreloading);
            put(TlsAnalyzedProperty.SUPPORTS_HPKP, supportsHpkp);
            put(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, supportsHpkpReportOnly);
            put(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, vulnerableBreach);
            put(TlsAnalyzedProperty.HSTS_INCLUDES_SUBDOMAINS, hstsIncludesSubdomains);
            put(TlsAnalyzedProperty.HPKP_INCLUDES_SUBDOMAINS, hpkpIncludesSubdomains);
            put(TlsAnalyzedProperty.HSTS_NOT_PARSEABLE, hstsNotParseable);
            put(TlsAnalyzedProperty.HPKP_NOT_PARSEABLE, hpkpNotParseable);
        } else {
            setPropertiesToCouldNotTest();
        }
        report.setHstsMaxAge(hstsMaxAge);
        report.setHpkpMaxAge(hpkpMaxAge);
        put(TlsAnalyzedProperty.NORMAL_HPKP_PINS, pinList);
        put(TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS, reportOnlyPinList);
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }
}
