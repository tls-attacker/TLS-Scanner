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

public class DtlsHelloVerifyRequestResult extends ProbeResult {

    private TestResult hasHvrRetransmissions;
    private TestResult checksCookie;
    private Integer cookieLength;
    private TestResult usesVersion;
    private TestResult usesRandom;
    private TestResult usesSessionId;
    private TestResult usesCiphersuites;
    private TestResult usesCompressions;

    public DtlsHelloVerifyRequestResult(TestResult hasHvrRetransmissions, TestResult checksCookie, Integer cookieLength,
        TestResult usesVersion, TestResult usesRandom, TestResult usesSessionId, TestResult usesCiphersuites,
        TestResult usesCompressions) {
        super(ProbeType.DTLS_HELLO_VERIFY_REQUEST);
        this.hasHvrRetransmissions = hasHvrRetransmissions;
        this.checksCookie = checksCookie;
        this.cookieLength = cookieLength;
        this.usesVersion = usesVersion;
        this.usesRandom = usesRandom;
        this.usesSessionId = usesSessionId;
        this.usesCiphersuites = usesCiphersuites;
        this.usesCompressions = usesCompressions;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.HAS_HVR_RETRANSMISSIONS, hasHvrRetransmissions);
        report.putResult(AnalyzedProperty.HAS_COOKIE_CHECKS, checksCookie);
        report.setCookieLength(cookieLength);
        report.putResult(AnalyzedProperty.USES_VERSION_FOR_COOKIE, usesVersion);
        report.putResult(AnalyzedProperty.USES_RANDOM_FOR_COOKIE, usesRandom);
        report.putResult(AnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, usesSessionId);
        report.putResult(AnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, usesCiphersuites);
        report.putResult(AnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, usesCompressions);
    }

}
