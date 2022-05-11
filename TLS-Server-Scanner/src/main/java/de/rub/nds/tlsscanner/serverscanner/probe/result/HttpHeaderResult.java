/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpHeaderResult extends ProbeResult<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<HttpsHeader> headerList = null;
    private TestResult speaksHttps = null;
    private TestResult supportsHsts = TestResults.FALSE;
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private TestResult hstsIncludesSubdomains = TestResults.FALSE;
    private TestResult hpkpIncludesSubdomains = TestResults.FALSE;
    private TestResult supportsHstsPreloading = TestResults.FALSE;
    private TestResult hstsNotParseable = null;
    private TestResult hpkpNotParseable = null;
    private TestResult supportsHpkp = TestResults.FALSE;
    private TestResult supportsHpkpReportOnly = TestResults.FALSE;
    private TestResult vulnerableBreach = TestResults.FALSE;

    public HttpHeaderResult(TestResult speaksHttps, List<HttpsHeader> headerList) {
        super(TlsProbeType.HTTP_HEADER);
        this.speaksHttps = speaksHttps;
        this.headerList = headerList;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_HTTPS, speaksHttps);
        report.setHeaderList(headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        if (headerList != null) {
            for (HttpsHeader header : headerList) {
                if (header.getHeaderName().getValue().equals("Strict-Transport-Security")) {
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
                                new HpkpPin(pinString[0], Base64.getDecoder().decode(pinString[1].replace("\"", "")));
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
                                HpkpPin pin = new HpkpPin(pinString[0],
                                    Base64.getDecoder().decode(pinString[1].replace("\"", "")));
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
                    String[] compressionAlgorithms =
                        { "compress", "deflate", "exi", "gzip", "br", "bzip2", "lzma", "xz" };
                    for (String compression : compressionAlgorithms) {
                        if (compressionHeaderValue.contains(compression)) {
                            vulnerableBreach = TestResults.TRUE;
                        }
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
        report.putResult(TlsAnalyzedProperty.SUPPORTS_HSTS, supportsHsts);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, supportsHstsPreloading);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_HPKP, supportsHpkp);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, supportsHpkpReportOnly);
        report.setHpkpMaxAge(hpkpMaxAge);
        report.setNormalHpkpPins(pinList);
        report.setReportOnlyHpkpPins(reportOnlyPinList);
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, vulnerableBreach);
    }

}
