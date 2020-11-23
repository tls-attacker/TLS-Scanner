package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class HttpFalseStartResult extends ProbeResult {

    private final TestResult supportsFalseStart;

    public HttpFalseStartResult(TestResult supportsFalseStart) {
        super(ProbeType.HTTP_FALSE_START);
        this.supportsFalseStart = supportsFalseStart;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_HTTP_FALSE_START, this.supportsFalseStart);
    }
}
