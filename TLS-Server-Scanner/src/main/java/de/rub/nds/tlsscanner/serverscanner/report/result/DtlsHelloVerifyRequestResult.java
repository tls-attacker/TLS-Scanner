/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class DtlsHelloVerifyRequestResult extends ProbeResult {

    private TestResult hasHvrRetransmissions;
    private TestResult checksCookie;
    private Integer cookieLength;
    private TestResult usesVersionInCookie;
    private TestResult usesRandomInCookie;
    private TestResult usesSessionIdInCookie;
    private TestResult usesCiphersuitesInCookie;
    private TestResult usesCompressionsInCookie;

    public DtlsHelloVerifyRequestResult(TestResult hasHvrRetransmissions, TestResult checksCookie, Integer cookieLength,
        TestResult usesVersionInCookie, TestResult usesRandomInCookie, TestResult usesSessionIdInCookie,
        TestResult usesCiphersuitesInCookie, TestResult usesCompressionsInCookie) {
        super(ProbeType.DTLS_HELLO_VERIFY_REQUEST);
        this.hasHvrRetransmissions = hasHvrRetransmissions;
        this.checksCookie = checksCookie;
        this.cookieLength = cookieLength;
        this.usesVersionInCookie = usesVersionInCookie;
        this.usesRandomInCookie = usesRandomInCookie;
        this.usesSessionIdInCookie = usesSessionIdInCookie;
        this.usesCiphersuitesInCookie = usesCiphersuitesInCookie;
        this.usesCompressionsInCookie = usesCompressionsInCookie;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.HAS_HVR_RETRANSMISSIONS, hasHvrRetransmissions);
        report.putResult(AnalyzedProperty.HAS_COOKIE_CHECKS, checksCookie);
        report.setCookieLength(cookieLength);
        report.putResult(AnalyzedProperty.USES_VERSION_FOR_COOKIE, usesVersionInCookie);
        report.putResult(AnalyzedProperty.USES_RANDOM_FOR_COOKIE, usesRandomInCookie);
        report.putResult(AnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, usesSessionIdInCookie);
        report.putResult(AnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, usesCiphersuitesInCookie);
        report.putResult(AnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, usesCompressionsInCookie);
    }

}
