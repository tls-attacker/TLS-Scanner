/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsCoookieResult extends ProbeResult {

    private TestResult checksCookie;
    private TestResult checksCookieWithClientParameters;

    public DtlsCoookieResult(TestResult checksCookie, TestResult checksCookieWithClientParameters) {
        super(ProbeType.DTLS_COOKIE);
        this.checksCookie = checksCookie;
        this.checksCookieWithClientParameters = checksCookieWithClientParameters;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.HAS_COOKIE_CHECKS, checksCookie);
        report.putResult(AnalyzedProperty.USES_CLIENT_PARAMERTS_FOR_COOKIE_CHECKS, checksCookieWithClientParameters);
    }

}
