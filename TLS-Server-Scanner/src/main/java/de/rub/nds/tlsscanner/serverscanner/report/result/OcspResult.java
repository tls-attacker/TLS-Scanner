/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ocsp.OcspCertificateResult;
import java.util.List;

/**
 *
 * @author Nils Hanke {@literal <nils.hanke@rub.de>}
 */
public class OcspResult extends ProbeResult {

    private final List<OcspCertificateResult> certResults;

    private final List<CertificateStatusRequestExtensionMessage> tls13CertStatus;

    public OcspResult(List<OcspCertificateResult> certResults,
        List<CertificateStatusRequestExtensionMessage> tls13CertStatus) {
        super(ProbeType.OCSP);
        this.certResults = certResults;
        this.tls13CertStatus = tls13CertStatus;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setOcspResults(certResults);

        report.putResult(AnalyzedProperty.SUPPORTS_OCSP, getConclusiveSupportsOcsp());

        report.putResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING, getConclusiveSupportsStapling());

        report.putResult(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, getConclusiveIncludesCertMessage());

        report.putResult(AnalyzedProperty.SUPPORTS_STAPLED_NONCE, getConclusiveSupportsStapledNonce());

        report.putResult(AnalyzedProperty.MUST_STAPLE, getConclusiveMustStaple());

        report.putResult(AnalyzedProperty.SUPPORTS_NONCE, getConclusiveSupportsNonce());

        report.putResult(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED, getConclusiveStapledResponseExpired());

        if (tls13CertStatus != null) {
            if (tls13CertStatus.size() == 1) {
                report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResult.TRUE);
                report.putResult(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResult.FALSE);
            } else if (tls13CertStatus.size() > 1) {
                report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResult.TRUE);
                report.putResult(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResult.TRUE);
            } else {
                report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResult.FALSE);
                report.putResult(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResult.FALSE);
            }
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, TestResult.COULD_NOT_TEST);
            report.putResult(AnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES, TestResult.COULD_NOT_TEST);
        }
    }

    private TestResult getConclusiveSupportsOcsp() {
        boolean foundFalse = false;
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (Boolean.TRUE.equals(result.getSupportsOcsp())) {
                    return TestResult.TRUE;
                } else if (Boolean.FALSE.equals(result.getSupportsOcsp())) {
                    foundFalse = true;
                }
            }

            if (foundFalse) {
                return TestResult.FALSE;
            }
        }
        return TestResult.ERROR_DURING_TEST;
    }

    private TestResult getConclusiveSupportsStapling() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isSupportsStapling()) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }

    private TestResult getConclusiveIncludesCertMessage() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.getStapledResponse() != null) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }

    private TestResult getConclusiveSupportsStapledNonce() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.getStapledResponse() != null && result.getStapledResponse().getNonce() != null) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }

    private TestResult getConclusiveMustStaple() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isMustStaple()) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }

    private TestResult getConclusiveSupportsNonce() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isSupportsNonce()) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }

    private TestResult getConclusiveStapledResponseExpired() {
        if (certResults != null) {
            for (OcspCertificateResult result : certResults) {
                if (result.isStapledResponseExpired()) {
                    return TestResult.TRUE;
                }
            }
        }
        return TestResult.FALSE;
    }
}
