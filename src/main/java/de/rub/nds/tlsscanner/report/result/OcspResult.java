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
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 *
 * @author Nils Hanke <nils.hanke@rub.de>
 */
public class OcspResult extends ProbeResult {

    private final boolean supportsStapling;
    private final boolean mustStaple;
    private final boolean supportsNonce;
    private final OCSPResponse stapledResponse;
    private final OCSPResponse firstResponse;
    private final OCSPResponse secondResponse;

    public OcspResult(boolean supportsStapling, boolean mustStaple, boolean supportsNonce,
            OCSPResponse stapledResponse, OCSPResponse firstResponse, OCSPResponse secondResponse) {
        super(ProbeType.OCSP);
        this.supportsStapling = supportsStapling;
        this.mustStaple = mustStaple;
        this.supportsNonce = supportsNonce;
        this.stapledResponse = stapledResponse;
        this.firstResponse = firstResponse;
        this.secondResponse = secondResponse;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportsStapling(supportsStapling);
        report.setMustStaple(mustStaple);
        report.setSupportsNonce(supportsNonce);
        report.setStapledOcspResponse(stapledResponse);
        report.setFirstOcspResponse(firstResponse);
        report.setSecondOcspResponse(secondResponse);

        // Check if status_request is supported, but no certificate status
        // request message was given
        if (supportsStapling && stapledResponse == null) {
            report.putResult(AnalyzedProperty.HAS_STAPLED_RESPONSE_DESPITE_SUPPORT, TestResult.FALSE);
        } else {
            report.putResult(AnalyzedProperty.HAS_STAPLED_RESPONSE_DESPITE_SUPPORT, TestResult.TRUE);
        }

        if (mustStaple) {
            report.putResult(AnalyzedProperty.MUST_STAPLE, TestResult.TRUE);
        } else {
            report.putResult(AnalyzedProperty.MUST_STAPLE, TestResult.FALSE);
        }

        if (firstResponse != null) {
            if (stapledResponse != null) {
                // Check if stapled response is older than a freshly requested
                // one
                DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
                LocalDateTime firstResponseTime = LocalDateTime
                        .parse(stapledResponse.getResponseTime(), inputFormatter);
                LocalDateTime secondResponseTime = LocalDateTime.parse(firstResponse.getResponseTime(), inputFormatter);

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
                if (firstResponse.getNonce().intValue() != 42) {
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
    }
}
