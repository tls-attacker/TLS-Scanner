package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class HttpHeaderResult extends ProbeResult {

    private List<HttpsHeader> headerList = null;
    private Boolean speaksHttps = null;
    private Boolean supportsHsts = null;
    private Boolean supportsHstsPreloading = null;
    private Boolean supportsHpkp = null;

    public HttpHeaderResult(boolean speaksHttps, List<HttpsHeader> headerList) {
        super(ProbeType.HTTP_HEADER);
        this.speaksHttps = speaksHttps;
        this.headerList = headerList;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSpeaksHttps(speaksHttps);
        report.setHeaderList(headerList);
        report.setSupportsHsts(supportsHsts);
        report.setSupportsHstsPreloading(supportsHstsPreloading);
        report.setSupportsHpkp(supportsHpkp);
    }

}
