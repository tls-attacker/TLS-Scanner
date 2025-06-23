/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import de.rub.nds.protocol.constants.HashAlgorithm;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.Certificate;

public class CertificateJudge {

    private final Certificate certificate;
    private final String domainName;
    private final CertificateReport report;

    /**
     * Constructs a CertificateJudge to evaluate certificate properties.
     *
     * @param certificate the certificate to evaluate
     * @param report the certificate report to use for evaluation
     * @param domainName the domain name to check against the certificate
     */
    public CertificateJudge(Certificate certificate, CertificateReport report, String domainName) {
        this.certificate = certificate;
        this.report = report;
        this.domainName = domainName;
    }

    /**
     * Checks if the certificate has expired.
     *
     * @return true if expired, false if valid, null if unable to determine
     */
    public Boolean checkExpired() {
        Boolean result = isCertificateExpired(report);
        return result;
    }

    /**
     * Checks if the certificate is not yet valid.
     *
     * @return true if valid, false if not yet valid, null if unable to determine
     */
    public Boolean checkNotYetValid() {
        Boolean result = isCertificateValidYet(report);
        return result;
    }

    /**
     * Checks if the certificate has been revoked.
     *
     * @return true if revoked, false if not revoked, null if unable to determine
     */
    public Boolean checkCertificateRevoked() {
        Boolean result = isRevoked(certificate);
        return result;
    }

    /**
     * Determines if the certificate uses a weak hash algorithm.
     *
     * @param report the certificate report containing hash algorithm information
     * @return true if weak algorithm (MD5, SHA1, or NONE), false otherwise, null if unknown
     */
    public Boolean isWeakHashAlgo(CertificateReport report) {
        if (report.getHashAlgorithm() != null) {
            HashAlgorithm algo = report.getHashAlgorithm();
            return algo == HashAlgorithm.MD5
                    || algo == HashAlgorithm.NONE
                    || algo == HashAlgorithm.SHA1;
        } else {
            return null;
        }
    }

    /**
     * Checks if the certificate contains a weak Debian key.
     *
     * @param report the certificate report containing key information
     * @return true if the key is a weak Debian key, false otherwise
     */
    public Boolean isWeakKey(CertificateReport report) {
        return report.getWeakDebianKey() == Boolean.TRUE;
    }

    /**
     * Checks if the certificate has expired based on its notAfter date.
     *
     * @param report the certificate report containing validity dates
     * @return true if expired, false if still valid, null if date unavailable
     */
    public Boolean isCertificateExpired(CertificateReport report) {
        if (report.getNotAfter() != null) {
            return report.getNotAfter().isBeforeNow();
        } else {
            return null;
        }
    }

    /**
     * Checks if the certificate is valid yet based on its notBefore date.
     *
     * @param report the certificate report containing validity dates
     * @return true if already valid, false if not yet valid, null if date unavailable
     */
    public Boolean isCertificateValidYet(CertificateReport report) {
        if (report.getNotBefore() != null) {
            return report.getNotBefore().isBeforeNow();
        } else {
            return null;
        }
    }

    /**
     * Checks if the certificate has been revoked.
     *
     * @param certificate the certificate to check
     * @return true if revoked, false if not revoked
     */
    public Boolean isRevoked(Certificate certificate) {
        // TODO
        return false;
    }

    /**
     * Checks if the certificate's subject or SAN fields match the given domain name.
     *
     * @param certificate the certificate to check
     * @param domainName the domain name to verify
     * @return true if domain name does not match, false if it matches
     */
    public Boolean domainNameDoesNotMatch(X509Certificate certificate, String domainName) {
        // TODO
        return false;
    }

    private Boolean isNotTrusted(X509Certificate certificate) {
        // TODO
        return false;
    }

    private Boolean isSelfSigned(X509Certificate certificate) {
        return false;
    }

    /**
     * Determines if the certificate is self-signed by verifying its signature with its own public
     * key.
     *
     * @return true if self-signed, false if not, null if unable to determine
     */
    public Boolean isSelfSigned() {
        try {
            // Try to verify certificate signature with its own public key
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert =
                    (X509Certificate)
                            certFactory.generateCertificate(
                                    new ByteArrayInputStream(certificate.getEncoded()));
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            return true;
        } catch (SignatureException | InvalidKeyException ex) {
            return false;
        } catch (CertificateException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | IOException e) {
            return null;
        }
    }

    private Boolean checkBlacklistedKey() {
        // if (isWeakKey(report)) {
        // tlsCheckList.add(new ConfigurationFlaw(domainName, FlawLevel.FATAL,
        // domainName, domainName));
        // }
        return null;
    }
}
