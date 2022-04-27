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
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;

public class OcspResult extends ProbeResult<ServerReport> {

    private final List<OcspCertificateResult> certResults;

    private final List<CertificateStatusRequestExtensionMessage> tls13CertStatus;

    public OcspResult(List<OcspCertificateResult> certResults,
        List<CertificateStatusRequestExtensionMessage> tls13CertStatus) {
        super(TlsProbeType.OCSP);
        this.certResults = certResults;
        this.tls13CertStatus = tls13CertStatus;
    }

    @Override
    public void mergeData(ServerReport report) {
        report.setOcspResults(certResults);

        report.putResult(TlsAnalyzedProperty.SUPPORTS_OCSP, getConclusiveSupportsOcsp());

        report.putResult(TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING, getConclusiveSupportsStapling());

        report.putResult(TlsAnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, getConclusiveIncludesCertMessage());

        report.putResult(TlsAnalyzedProperty.SUPPORTS_STAPLED_NONCE, getConclusiveSupportsStapledNonce());

        report.putResult(TlsAnalyzedProperty.MUST_STAPLE, getConclusiveMustStaple());

        report.putResult(TlsAnalyzedProperty.SUPPORTS_NONCE, getConclusiveSupportsNonce());

        report.putResult(TlsAnalyzedProperty.STAPLED_RESPONSE_EXPIRED, getConclusiveStapledResponseExpired());

        if (tls13CertStatus != null) {
            if (tls13CertStatus.size() == 1) {
                report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.TRUE);
                report.putResult(TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.FALSE);
            } else if (tls13CertStatus.size() > 1) {
                report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.TRUE);
                report.putResult(TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.TRUE);
            } else {
                report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.FALSE);
                report.putResult(TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.FALSE);
            }
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResults.COULD_NOT_TEST);
        }
    }

    private TestResult getConclusiveSupportsOcsp() {
        boolean foundFalse = false;
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (Boolean.TRUE.equals(result.getSupportsOcsp())) {
                    return TestResults.TRUE;
                } else if (Boolean.FALSE.equals(result.getSupportsOcsp())) {
                    foundFalse = true;
                }
            }

            if (foundFalse) {
                return TestResults.FALSE;
            }
        }
        return TestResults.ERROR_DURING_TEST;
    }

    private TestResult getConclusiveSupportsStapling() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isSupportsStapling()) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveIncludesCertMessage() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.getStapledResponse() != null) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveSupportsStapledNonce() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.getStapledResponse() != null && result.getStapledResponse().getNonce() != null) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveMustStaple() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isMustStaple()) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveSupportsNonce() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isSupportsNonce()) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }

    private TestResult getConclusiveStapledResponseExpired() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isStapledResponseExpired()) {
                    return TestResults.TRUE;
                }
            }
        }
        return TestResults.FALSE;
    }
}
