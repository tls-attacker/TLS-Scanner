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
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class DtlsHelloVerifyRequestResult extends ProbeResult<ServerReport> {

    private TestResult hasHvrRetransmissions;
    private TestResult checksCookie;
    private Integer cookieLength;
    private TestResult usesIpAdressInCookie;
    private TestResult usesPortInCookie;
    private TestResult usesVersionInCookie;
    private TestResult usesRandomInCookie;
    private TestResult usesSessionIdInCookie;
    private TestResult usesCiphersuitesInCookie;
    private TestResult usesCompressionsInCookie;

    public DtlsHelloVerifyRequestResult(TestResult hasHvrRetransmissions, TestResult checksCookie, Integer cookieLength,
        TestResult usesIpAdressInCookie, TestResult usesPortInCookie, TestResult usesVersionInCookie,
        TestResult usesRandomInCookie, TestResult usesSessionIdInCookie, TestResult usesCiphersuitesInCookie,
        TestResult usesCompressionsInCookie) {
        super(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST);
        this.hasHvrRetransmissions = hasHvrRetransmissions;
        this.checksCookie = checksCookie;
        this.cookieLength = cookieLength;
        this.usesIpAdressInCookie = usesIpAdressInCookie;
        this.usesPortInCookie = usesPortInCookie;
        this.usesVersionInCookie = usesVersionInCookie;
        this.usesRandomInCookie = usesRandomInCookie;
        this.usesSessionIdInCookie = usesSessionIdInCookie;
        this.usesCiphersuitesInCookie = usesCiphersuitesInCookie;
        this.usesCompressionsInCookie = usesCompressionsInCookie;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS, hasHvrRetransmissions);
        report.putResult(TlsAnalyzedProperty.HAS_COOKIE_CHECKS, checksCookie);
        report.setCookieLength(cookieLength);
        report.putResult(TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE, usesIpAdressInCookie);
        report.putResult(TlsAnalyzedProperty.USES_PORT_FOR_COOKIE, usesPortInCookie);
        report.putResult(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE, usesVersionInCookie);
        report.putResult(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE, usesRandomInCookie);
        report.putResult(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, usesSessionIdInCookie);
        report.putResult(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, usesCiphersuitesInCookie);
        report.putResult(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, usesCompressionsInCookie);
    }

}
