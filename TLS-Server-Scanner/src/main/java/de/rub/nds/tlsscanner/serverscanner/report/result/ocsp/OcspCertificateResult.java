/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.ocsp;

import de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateStatus;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.OcspProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class OcspCertificateResult {
    private Boolean supportsOcsp;
    private boolean supportsStapling;
    private boolean mustStaple;
    private boolean supportsNonce;
    private OCSPResponse stapledResponse;
    private OCSPResponse firstResponse;
    private OCSPResponse secondResponse;
    private OCSPResponse httpGetResponse;

    private final CertificateChain certificate;

    public OcspCertificateResult(CertificateChain certificate) {
        this.certificate = certificate;
    }

    public OcspCertificateResult(CertificateChain certificate, Boolean supportsOcsp, boolean supportsStapling,
        boolean mustStaple, boolean supportsNonce, OCSPResponse stapledResponse, OCSPResponse firstResponse,
        OCSPResponse secondResponse, OCSPResponse httpGetResponse) {
        this.certificate = certificate;
        this.supportsOcsp = supportsOcsp;
        this.supportsStapling = supportsStapling;
        this.mustStaple = mustStaple;
        this.supportsNonce = supportsNonce;
        this.stapledResponse = stapledResponse;
        this.firstResponse = firstResponse;
        this.secondResponse = secondResponse;
        this.httpGetResponse = httpGetResponse;
    }

    public Boolean getSupportsOcsp() {
        return supportsOcsp;
    }

    public boolean isSupportsStapling() {
        return supportsStapling;
    }

    public boolean isMustStaple() {
        return mustStaple;
    }

    public boolean isSupportsNonce() {
        return supportsNonce;
    }

    public OCSPResponse getStapledResponse() {
        return stapledResponse;
    }

    public OCSPResponse getFirstResponse() {
        return firstResponse;
    }

    public OCSPResponse getSecondResponse() {
        return secondResponse;
    }

    public OCSPResponse getHttpGetResponse() {
        return httpGetResponse;
    }

    public CertificateChain getCertificate() {
        return certificate;
    }

    public void setSupportsOcsp(Boolean supportsOcsp) {
        this.supportsOcsp = supportsOcsp;
    }

    public void setSupportsStapling(boolean supportsStapling) {
        this.supportsStapling = supportsStapling;
    }

    public void setMustStaple(boolean mustStaple) {
        this.mustStaple = mustStaple;
    }

    public void setSupportsNonce(boolean supportsNonce) {
        this.supportsNonce = supportsNonce;
    }

    public void setStapledResponse(OCSPResponse stapledResponse) {
        this.stapledResponse = stapledResponse;
    }

    public void setFirstResponse(OCSPResponse firstResponse) {
        this.firstResponse = firstResponse;
    }

    public void setSecondResponse(OCSPResponse secondResponse) {
        this.secondResponse = secondResponse;
    }

    public void setHttpGetResponse(OCSPResponse httpGetResponse) {
        this.httpGetResponse = httpGetResponse;
    }

    public boolean isStapledResponseExpired() {
        if (firstResponse != null && firstResponse.getResponseStatus() == 0) {
            if (stapledResponse != null && stapledResponse.getResponseStatus() == 0) {
                DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);

                // Check if status is actually outdated and not valid anymore
                CertificateStatus certificateStatus = stapledResponse.getCertificateStatusList().get(0);
                LocalDateTime certificateStatusUpdateValidTill =
                    LocalDateTime.parse(certificateStatus.getTimeOfNextUpdate(), inputFormatter);
                LocalDateTime currentTime = LocalDateTime.now();

                if (certificateStatusUpdateValidTill.isBefore(currentTime)) {
                    return true;
                }
            }
        }
        return false;

    }

    public long getDifferenceHoursStapled() {
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
                return difference.toHours();
            }
        }
        return -1;
    }

    public boolean isNonceMismatch() {
        // Check if the use of a nonce is supported
        if (supportsNonce) {
            // Check if the client nonce was used
            if (firstResponse.getNonce().intValue() != OcspProbe.NONCE_TEST_VALUE_1) {
                return true;
            } else if (secondResponse != null) {
                // Check if a nonce was reused, e.g. caching didn't respect given client nonce
                if (firstResponse.getNonce().equals(secondResponse.getNonce())) {
                    return true;
                } else {
                    return false;
                }
            }
        }
        return false;
    }

    public boolean isSupportsStapledNonce() {
        if (stapledResponse != null && stapledResponse.getNonce() != null) {
            return true;
        } else {
            return false;
        }
    }
}
