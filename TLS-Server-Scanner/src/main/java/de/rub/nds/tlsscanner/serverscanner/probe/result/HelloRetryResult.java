/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class HelloRetryResult extends ProbeResult<ServerReport> {

    private final TestResult sentHelloRetryRequest;
    private final TestResult sentCookie;
    private final NamedGroup serversChosenGroup;

    public HelloRetryResult(
            TestResult sentHelloRetryRequest,
            TestResult sentCookie,
            NamedGroup serversChosenGroup) {
        super(TlsProbeType.HELLO_RETRY);
        this.sentCookie = sentCookie;
        this.sentHelloRetryRequest = sentHelloRetryRequest;
        this.serversChosenGroup = serversChosenGroup;
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (sentCookie != null) {
            report.putResult(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, sentCookie);
        } else {
            report.putResult(
                    TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY,
                    TestResults.ERROR_DURING_TEST);
        }

        if (sentHelloRetryRequest != null) {
            report.putResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, sentHelloRetryRequest);
        } else {
            report.putResult(
                    TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, TestResults.ERROR_DURING_TEST);
        }

        report.setHelloRetryRequestSelectedNamedGroup(serversChosenGroup);
    }
}
