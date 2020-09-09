/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateStatus;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.OcspProbe;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 *
 * @author Nils Hanke <nils.hanke@rub.de>
 */
public class OcspResult extends ProbeResult {

    private final Boolean supportsOcsp;
    private final boolean supportsStapling;
    private final boolean mustStaple;
    private final boolean supportsNonce;
    private final OCSPResponse stapledResponse;
    private final OCSPResponse firstResponse;
    private final OCSPResponse secondResponse;
    private final OCSPResponse httpGetResponse;

    private final List<CertificateStatusRequestExtensionMessage> tls13CertStatus;

    public OcspResult(Boolean supportsOcsp, boolean supportsStapling, boolean mustStaple, boolean supportsNonce,
            OCSPResponse stapledResponse, OCSPResponse firstResponse, OCSPResponse secondResponse,
            OCSPResponse httpGetResponse, List<CertificateStatusRequestExtensionMessage> tls13CertStatus) {
        super(ProbeType.OCSP);
        this.supportsOcsp = supportsOcsp;
        this.supportsStapling = supportsStapling;
        this.mustStaple = mustStaple;
        this.supportsNonce = supportsNonce;
        this.stapledResponse = stapledResponse;
        this.firstResponse = firstResponse;
        this.secondResponse = secondResponse;
        this.httpGetResponse = httpGetResponse;
        this.tls13CertStatus = tls13CertStatus;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setStapledOcspResponse(stapledResponse);
        report.setFirstOcspResponse(firstResponse);
        report.setSecondOcspResponse(secondResponse);
        report.setHttpGetOcspResponse(httpGetResponse);

        // Check if status_request is supported, but no certificate status
        // request message was given

        if (Boolean.TRUE.equals(supportsOcsp)) {
            report.putResult(AnalyzedProperty.SUPPORTS_OCSP, TestResult.TRUE);
        } else if (Boolean.FALSE.equals(supportsOcsp)) {
            report.putResult(AnalyzedProperty.SUPPORTS_OCSP, TestResult.FALSE);
        } else if (supportsOcsp == null) {
            report.putResult(AnalyzedProperty.SUPPORTS_OCSP, TestResult.ERROR_DURING_TEST);
        }

        if (supportsStapling) {
            report.putResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_OCSP_STAPLING, TestResult.FALSE);
        }

        if (stapledResponse != null) {
            report.putResult(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, TestResult.FALSE);
        }

        if (stapledResponse != null && stapledResponse.getNonce() != null) {
            report.putResult(AnalyzedProperty.SUPPORTS_STAPLED_NONCE, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_STAPLED_NONCE, TestResult.FALSE);
        }

        if (mustStaple) {
            report.putResult(AnalyzedProperty.MUST_STAPLE, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.MUST_STAPLE, TestResult.FALSE);
        }

        if (firstResponse != null && firstResponse.getResponseStatus() == 0) {
            if (stapledResponse != null && stapledResponse.getResponseStatus() == 0) {
                // Check if stapled response is older than a freshly requested
                // one
                DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
                LocalDateTime firstResponseTime = LocalDateTime.parse(stapledResponse.getProducedAt(), inputFormatter);
                LocalDateTime secondResponseTime = LocalDateTime.parse(firstResponse.getProducedAt(), inputFormatter);

                // Check how long the stapled response has been cached for, in
                // hours
                Duration difference = Duration.between(firstResponseTime, secondResponseTime);
                long differenceInHours = difference.toHours();
                report.setDifferenceHoursStapled(differenceInHours);

                // Check if status is actually outdated and not valid anymore
                CertificateStatus certificateStatus = stapledResponse.getCertificateStatusList().get(0);
                LocalDateTime certificateStatusUpdateValidTill = LocalDateTime.parse(
                        certificateStatus.getTimeOfNextUpdate(), inputFormatter);
                LocalDateTime currentTime = LocalDateTime.now();

                if (certificateStatusUpdateValidTill.isBefore(currentTime)) {
                    report.putResult(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED, TestResult.TRUE);
                } else {
                    report.putResult(AnalyzedProperty.STAPLED_RESPONSE_EXPIRED, TestResult.FALSE);
                }
            }
            // Check if the use of a nonce is supported
            if (supportsNonce) {
                report.putResult(AnalyzedProperty.SUPPORTS_NONCE, TestResult.TRUE);

                // Check if the client nonce was used
                if (firstResponse.getNonce().intValue() != OcspProbe.NONCE_TEST_VALUE_1) {
                    report.putResult(AnalyzedProperty.NONCE_MISMATCH, TestResult.TRUE);
                }
                // Check if a nonce was reused, e.g. caching didn't respect
                // given client nonce
                else if (secondResponse != null) {
                    if (firstResponse.getNonce().equals(secondResponse.getNonce())) {
                        report.putResult(AnalyzedProperty.NONCE_MISMATCH, TestResult.TRUE);
                    } else {
                        report.putResult(AnalyzedProperty.NONCE_MISMATCH, TestResult.FALSE);
                    }
                }
            } else {
                report.putResult(AnalyzedProperty.SUPPORTS_NONCE, TestResult.FALSE);
            }
        }

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
}
