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
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.Certificate;

public class CertificateJudge {

    private final Certificate certificate;
    private final String domainName;
    private final CertificateReport report;

    public CertificateJudge(Certificate certificate, CertificateReport report, String domainName) {
        this.certificate = certificate;
        this.report = report;
        this.domainName = domainName;
    }

    public Boolean checkExpired() {
        Boolean result = isCertificateExpired(report);
        return result;
    }

    public Boolean checkNotYetValid() {
        Boolean result = isCertificateValidYet(report);
        return result;
    }

    public Boolean checkCertificateRevoked() {
        Boolean result = isRevoked(certificate);
        return result;
    }

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

    public Boolean isWeakKey(CertificateReport report) {
        return report.getWeakDebianKey() == Boolean.TRUE;
    }

    public Boolean isCertificateExpired(CertificateReport report) {
        if (report.getNotAfter() != null) {
            return report.getNotAfter().isBeforeNow();
        } else {
            return null;
        }
    }

    public Boolean isCertificateValidYet(CertificateReport report) {
        if (report.getNotBefore() != null) {
            return report.getNotBefore().isBeforeNow();
        } else {
            return null;
        }
    }

    public Boolean isRevoked(Certificate certificate) {
        // TODO
        return false;
    }

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
        } catch (Exception e) {
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
