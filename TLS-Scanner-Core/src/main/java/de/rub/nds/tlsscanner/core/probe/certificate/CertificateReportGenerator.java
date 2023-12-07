/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.tlsscanner.core.probe.certificate.roca.RocaBrokenKey;
import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.Extensions;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateReportGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<CertificateReport> generateReports(X509CertificateChain certs) {
        List<CertificateReport> reportList = new LinkedList<>();
        if (certs != null) {
            for (de.rub.nds.x509attacker.x509.model.X509Certificate cert :
                    certs.getCertificateList()) {
                reportList.add(generateReport(cert));
            }
        }
        return reportList;
    }

    public static CertificateReport generateReport(X509Certificate cert) {
        CertificateReport report = new CertificateReport();
        setSubject(report, cert);
        setCommonNames(report, cert);
        // setAlternativeNames(report, cert); TODO
        setValidFrom(report, cert);
        setValidTo(report, cert);
        setPubkey(report, cert);
        setWeakDebianKey(report, cert);
        setIssuer(report, cert);
        setSignatureAlgorithm(report, cert);
        setHashAlgorithm(report, cert);
        setX509SignatureAlgorithm(cert, report);
        setSignatureAlgorithmOid(cert, report);
        setExtendedValidation(report, cert);
        setCertificateTransparency(report, cert);
        setOcspMustStaple(report, cert);
        setCrlSupported(report, cert);
        setOcspSupported(report, cert);
        setRevoked(report, cert);
        setDnsCca(report, cert);
        setSha256Hash(report, cert);
        setExtendedKeyUsage(report, cert);
        setVulnerableRoca(report, cert);

        TrustAnchorManager anchorManger = TrustAnchorManager.getInstance();
        if (anchorManger.isInitialized()) {
            report.setTrustAnchor(anchorManger.isTrustAnchor(report));
            report.setCustomTrustAnchor(anchorManger.isCustomTrustAnchor(report));
        } else {
            report.setTrustAnchor(null);
        }
        if (report.getIssuer().equals(report.getSubject())) {
            report.setSelfSigned(true);
        } else {
            report.setSelfSigned(false);
        }
        return report;
    }

    private static void setSignatureAlgorithmOid(X509Certificate cert, CertificateReport report) {
        report.setSignatureAndHashAlgorithmOid(cert.getX509SignatureAlgorithmObjectIdentifier());
    }

    private static void setX509SignatureAlgorithm(X509Certificate cert, CertificateReport report) {
        report.setX509SignatureAlgorithm(cert.getX509SignatureAlgorithm());
    }

    private static void setHashAlgorithm(CertificateReport report, X509Certificate cert) {
        report.setHashAlgorithm(cert.getHashAlgorithm());
    }

    private static void setSignatureAlgorithm(CertificateReport report, X509Certificate cert) {
        report.setSignatureAlgorithm(cert.getSignatureAlgorithm());
    }

    private static void setSubject(CertificateReport report, X509Certificate cert) {
        report.setSubject(cert.getSubjectString());
    }

    private static void setExtendedKeyUsage(CertificateReport report, X509Certificate cert) {
        Extensions extensions = cert.getTbsCertificate().getExplicitExtensions().getInnerField();
        for (Extension extension : extensions.getExtensionList()) {
            // TODO
        }
    }

    private static void setCommonNames(CertificateReport report, X509Certificate cert) {
        report.setCommonName(cert.getCommonName());
    }

    private static void setAlternativeNames(CertificateReport report, X509Certificate cert) {
        report.setAlternativeNames(cert.getSubjectAlternativeNames());
    }

    private static void setValidFrom(CertificateReport report, X509Certificate cert) {
        report.setNotBefore(cert.getNotBefore());
    }

    private static void setValidTo(CertificateReport report, X509Certificate cert) {
        report.setNotAfter(cert.getNotAfter());
    }

    private static void setPubkey(CertificateReport report, X509Certificate cert) {
        if (cert.getPublicKeyContainer() != null) {
            report.setPublicKey(cert.getPublicKeyContainer());
        }
    }

    private static void setWeakDebianKey(CertificateReport report, X509Certificate cert) {}

    private static void setIssuer(CertificateReport report, X509Certificate cert) {
        report.setIssuer(cert.getIssuerString());
    }

    private static void setExtendedValidation(CertificateReport report, X509Certificate cert) {}

    private static void setCertificateTransparency(
            CertificateReport report, X509Certificate cert) {}

    private static void setOcspMustStaple(CertificateReport report, X509Certificate cert) {
        try {
            Boolean mustStaple = null; // TODO ocspCertInfoExtractor.getMustStaple();
            if (mustStaple != null) {
                report.setOcspMustStaple(mustStaple);
            }
        } catch (Exception e) {
            LOGGER.debug("Could not extract OCSP 'must-staple' information from certificate.");
        }
    }

    private static void setCrlSupported(CertificateReport report, X509Certificate cert) {}

    private static void setOcspSupported(CertificateReport report, X509Certificate cert) {
        String ocspUrl = null; // TODO ocspCertInfoExtractor.getOcspServerUrl();
        report.setOcspSupported(ocspUrl != null);
    }

    private static void setRevoked(CertificateReport report, X509Certificate cert) {
        // TODO
    }

    private static void setDnsCca(CertificateReport report, X509Certificate cert) {}

    private static void setSha256Hash(CertificateReport report, X509Certificate cert) {
        report.setSha256Fingerprint(cert.getSha256Fingerprint());
    }

    private static void setVulnerableRoca(CertificateReport report, X509Certificate cert) {
        if (report.getPublicKey() != null && report.getPublicKey() instanceof RsaPublicKey) {
            RsaPublicKey pubkey = (RsaPublicKey) report.getPublicKey();
            report.setRocaVulnerable(RocaBrokenKey.isAffected(pubkey));
        } else {
            report.setRocaVulnerable(false);
        }
    }
}
