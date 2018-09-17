package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

public class HttpHeaderResult extends ProbeResult {

    private List<HttpsHeader> headerList = null;
    private Boolean speaksHttps = null;
    private Boolean supportsHsts = false;
    private Integer hstsMaxAge = null;
    private Integer hpkpMaxAge = null;
    private Boolean hstsCeasing = null;
    private Boolean hstsIncludesSubdomains = false;
    private Boolean hpkpIncludesSubdomains = false;
    private Boolean supportsHstsPreloading = false;
    private Boolean hstsNotParseable = null;
    private Boolean hpkpNotParseable = null;
    private Boolean supportsHpkp = false;
    private Boolean supportsHpkpReportOnly = false;
    private Boolean vulnerableBreach = false;

    public HttpHeaderResult(boolean speaksHttps, List<HttpsHeader> headerList) {
        super(ProbeType.HTTP_HEADER);
        this.speaksHttps = speaksHttps;
        this.headerList = headerList;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSpeaksHttps(speaksHttps);
        report.setHeaderList(headerList);
        List<HpkpPin> pinList = new LinkedList<>();
        List<HpkpPin> reportOnlyPinList = new LinkedList<>();
        for (HttpsHeader header : headerList) {
            if (header.getHeaderName().getValue().equals("Strict-Transport-Security")) {
                supportsHsts = true;
                boolean preload = false;
                String[] values = header.getHeaderValue().getValue().split(";");
                for (String value : values) {
                    if (value.trim().startsWith("preload")) {
                        preload = true;
                    }
                    if (value.trim().startsWith("includeSubDomains")) {
                        hstsIncludesSubdomains = true;
                    }
                    if (value.trim().startsWith("max-age")) {
                        String[] maxAge = value.split("=");
                        if (maxAge.length == 2) {
                            try {
                                hstsMaxAge = Integer.parseInt(maxAge[1].trim());
                            } catch (Exception E) {
                                E.printStackTrace();
                                hstsNotParseable = true;
                            }
                        } else {
                            hstsNotParseable = false;
                        }
                    }
                }
                supportsHstsPreloading = preload;
            }
            if (header.getHeaderName().getValue().equals("Public-Key-Pins")) {
                supportsHpkp = true;
                String[] values = header.getHeaderValue().getValue().split(";");
                for (String value : values) {
                    if (value.trim().startsWith("includeSubDomains")) {
                        hpkpIncludesSubdomains = true;
                    }
                    if (value.trim().startsWith("max-age")) {
                        String[] maxAge = value.split("=");
                        if (maxAge.length == 2) {
                            try {
                                hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                            } catch (Exception E) {
                                E.printStackTrace();
                                hpkpNotParseable = true;
                            }
                        } else {
                            hpkpNotParseable = false;
                        }
                    }
                    if (value.trim().startsWith("pin-")) {
                        String[] pinString = value.split("=");
                        HpkpPin pin = new HpkpPin(pinString[0], Base64.getDecoder().decode(pinString[1].replace("\"", "")));
                        pinList.add(pin);
                    }
                }
            }
            if (header.getHeaderName().getValue().equals("Public-Key-Pins-Report-Only")) {
                supportsHpkpReportOnly = true;
                String[] values = header.getHeaderValue().getValue().split(";");
                for (String value : values) {
                    if (value.trim().startsWith("includeSubDomains")) {
                        hpkpIncludesSubdomains = true;
                    }
                    if (value.trim().startsWith("max-age")) {
                        String[] maxAge = value.split("=");
                        if (maxAge.length == 2) {
                            try {
                                hpkpMaxAge = Integer.parseInt(maxAge[1].trim());
                            } catch (Exception E) {
                                E.printStackTrace();
                                hpkpNotParseable = true;
                            }
                        } else {
                            hpkpNotParseable = false;
                        }
                    }
                    if (value.trim().startsWith("pin-")) {
                        String[] pinString = value.split("=");
                        HpkpPin pin = new HpkpPin(pinString[0], Base64.getDecoder().decode(pinString[1].replace("\"", "")));
                        reportOnlyPinList.add(pin);
                    }
                }
            }
            if (header.getHeaderName().getValue().equals("Content-Encoding")) {
                String compressionHeaderValue = header.getHeaderValue().getValue();
                String[] compressionAlgorithms = {"compress", "deflate", "exi", "gzip", "br", "bzip2", "lzma", "xz"};
                for (String compression : compressionAlgorithms) {
                    if (compressionHeaderValue.contains(compression)) {
                        vulnerableBreach = true;
                    }
                }
            }
        }
        report.setHstsMaxAge(hstsMaxAge);
        report.setSupportsHsts(supportsHsts);
        report.setSupportsHstsPreloading(supportsHstsPreloading);
        report.setSupportsHpkp(supportsHpkp);
        report.setSupportsHpkpReportOnly(supportsHpkpReportOnly);
        report.setHpkpMaxAge(hpkpMaxAge);
        report.setNormalHpkpPins(pinList);
        report.setReportOnlyHpkpPins(reportOnlyPinList);
        report.setBreachVulnerable(vulnerableBreach);
    }

}
