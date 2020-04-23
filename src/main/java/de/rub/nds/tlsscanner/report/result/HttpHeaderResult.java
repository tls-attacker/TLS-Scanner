/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpHeaderResult extends ProbeResult {

    private final static Logger LOGGER = LogManager.getLogger();

    private List<HttpsHeader> headerList = null;
    private TestResult speaksHttps = null;
    private TestResult supportsHsts = TestResult.FALSE;
    private Long hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private TestResult hstsIncludesSubdomains = TestResult.FALSE;
    private TestResult hpkpIncludesSubdomains = TestResult.FALSE;
    private TestResult supportsHstsPreloading = TestResult.FALSE;
    private TestResult hstsNotParseable = null;
    private TestResult hpkpNotParseable = null;
    private TestResult supportsHpkp = TestResult.FALSE;
    private TestResult supportsHpkpReportOnly = TestResult.FALSE;
    private TestResult vulnerableBreach = TestResult.FALSE;

    public HttpHeaderResult(TestResult speaksHttps, List<HttpsHeader> headerList) {
        super(ProbeType.HTTP_HEADER);
        this.speaksHttps = speaksHttps;
        this.headerList = headerList;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_HTTPS, speaksHttps);
        report.setHeaderList(headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        if (headerList != null) {
            for (HttpsHeader header : headerList) {
                if (header.getHeaderName().getValue().equals("Strict-Transport-Security")) {
                    supportsHsts = TestResult.TRUE;
                    boolean preload = false;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("preload")) {
                            preload = true;
                        }
                        if (value.trim().startsWith("includeSubDomains")) {
                            hstsIncludesSubdomains = TestResult.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hstsMaxAge = Long.parseLong(maxAge[1].trim());
                                } catch (Exception E) {
                                    LOGGER.warn("HSTS was not parseable", E);
                                    hstsNotParseable = TestResult.TRUE;
                                }
                            } else {
                                hstsNotParseable = TestResult.FALSE;
                            }
                        }
                    }
                    supportsHstsPreloading = preload == true ? TestResult.TRUE : TestResult.FALSE;
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins")) {
                    supportsHpkp = TestResult.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("includeSubDomains")) {
                            hpkpIncludesSubdomains = TestResult.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception E) {
                                    LOGGER.warn("HPKP was not parseable", E);
                                    hpkpNotParseable = TestResult.TRUE;
                                }
                            } else {
                                hpkpNotParseable = TestResult.FALSE;
                            }
                        }
                        if (value.trim().startsWith("pin-")) {
                            String[] pinString = value.split("=");
                            HpkpPin pin = new HpkpPin(pinString[0], Base64.getDecoder().decode(
                                    pinString[1].replace("\"", "")));
                            pinList.add(pin);
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Public-Key-Pins-Report-Only")) {
                    supportsHpkpReportOnly = TestResult.TRUE;
                    String[] values = header.getHeaderValue().getValue().split(";");
                    for (String value : values) {
                        if (value.trim().startsWith("includeSubDomains")) {
                            hpkpIncludesSubdomains = TestResult.TRUE;
                        }
                        if (value.trim().startsWith("max-age")) {
                            String[] maxAge = value.split("=");
                            if (maxAge.length == 2) {
                                try {
                                    hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                                } catch (Exception E) {
                                    LOGGER.warn("HPKP was not parseable", E);
                                    hpkpNotParseable = TestResult.TRUE;
                                }
                            } else {
                                hpkpNotParseable = TestResult.FALSE;
                            }
                        }
                        if (value.trim().startsWith("pin-")) {
                            String[] pinString = value.split("=");
                            HpkpPin pin = new HpkpPin(pinString[0], Base64.getDecoder().decode(
                                    pinString[1].replace("\"", "")));
                            reportOnlyPinList.add(pin);
                        }
                    }
                }
                if (header.getHeaderName().getValue().equals("Content-Encoding")) {
                    String compressionHeaderValue = header.getHeaderValue().getValue();
                    String[] compressionAlgorithms = {"compress", "deflate", "exi", "gzip", "br", "bzip2", "lzma",
                        "xz"};
                    for (String compression : compressionAlgorithms) {
                        if (compressionHeaderValue.contains(compression)) {
                            vulnerableBreach = TestResult.TRUE;
                        }
                    }
                }
            }
        } else {
            supportsHsts = TestResult.COULD_NOT_TEST;
            supportsHstsPreloading = TestResult.COULD_NOT_TEST;
            supportsHpkp = TestResult.COULD_NOT_TEST;
            supportsHpkpReportOnly = TestResult.COULD_NOT_TEST;
            vulnerableBreach = TestResult.COULD_NOT_TEST;
        }
        report.setHstsMaxAge(hstsMaxAge);
        report.putResult(AnalyzedProperty.SUPPORTS_HSTS, supportsHsts);
        report.putResult(AnalyzedProperty.SUPPORTS_HSTS_PRELOADING, supportsHstsPreloading);
        report.putResult(AnalyzedProperty.SUPPORTS_HPKP, supportsHpkp);
        report.putResult(AnalyzedProperty.SUPPORTS_HPKP_REPORTING, supportsHpkpReportOnly);
        report.setHpkpMaxAge(hpkpMaxAge);
        report.setNormalHpkpPins(pinList);
        report.setReportOnlyHpkpPins(reportOnlyPinList);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_BREACH, vulnerableBreach);
    }

}
