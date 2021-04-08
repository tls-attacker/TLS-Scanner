/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class HelloRetryResult extends ProbeResult {

    private final TestResult sendsHelloRetryRequest;
    private final TestResult issuesCookie;

    public HelloRetryResult(TestResult sentHelloRetryRequest, TestResult sentCookie) {
        super(ProbeType.HELLO_RETRY);
        issuesCookie = sentCookie;
        sendsHelloRetryRequest = sentHelloRetryRequest;
    }

    @Override
    protected void mergeData(SiteReport report) {
        if (issuesCookie != null) {
            report.putResult(AnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, issuesCookie);
        } else {
            report.putResult(AnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, TestResult.ERROR_DURING_TEST);
        }

        if (sendsHelloRetryRequest != null) {
            report.putResult(AnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, sendsHelloRetryRequest);
        } else {
            report.putResult(AnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, TestResult.ERROR_DURING_TEST);
        }
    }
}
