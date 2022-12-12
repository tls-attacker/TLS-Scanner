/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class DtlsHelloVerifyRequestResult extends ProbeResult<ClientReport> {

    private final TestResult acceptsLegacyServerVersionMismatch;
    private final TestResult acceptsHvrSequenceNumberMismatch;
    private final TestResult acceptsServerHelloSequenceNumberMismatch;
    private final TestResult hasClientHelloMismatch;
    private final TestResult acceptsEmptyCookie;

    public DtlsHelloVerifyRequestResult(
            TestResult acceptsServerVersionMismatch,
            TestResult acceptsHVRSequenceNumberMismatch,
            TestResult acceptsServerHelloSequenceNumberMismatch,
            TestResult hasClientHelloMismatch,
            TestResult acceptsEmptyCookie) {
        super(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST);
        this.acceptsLegacyServerVersionMismatch = acceptsServerVersionMismatch;
        this.acceptsHvrSequenceNumberMismatch = acceptsHVRSequenceNumberMismatch;
        this.acceptsServerHelloSequenceNumberMismatch = acceptsServerHelloSequenceNumberMismatch;
        this.hasClientHelloMismatch = hasClientHelloMismatch;
        this.acceptsEmptyCookie = acceptsEmptyCookie;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH,
                acceptsLegacyServerVersionMismatch);
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH,
                acceptsHvrSequenceNumberMismatch);
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
                acceptsServerHelloSequenceNumberMismatch);
        report.putResult(TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH, hasClientHelloMismatch);
        report.putResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, acceptsEmptyCookie);
    }
}
