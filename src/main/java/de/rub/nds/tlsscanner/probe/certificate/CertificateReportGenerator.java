/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.probe.certificate.roca.BrokenKey;
import de.rub.nds.tlsscanner.trust.TrustAnchorManager;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateReportGenerator {

    private static final Logger LOGGER = LogManager.getLogger(CertificateReportGenerator.class.getName());

    public static List<CertificateReport> generateReports(Certificate certs) {
        List<CertificateReport> reportList = new LinkedList<>();
        if (certs != null) {
            for (org.bouncycastle.asn1.x509.Certificate cert : certs.getCertificateList()) {
                reportList.add(generateReport(cert));
            }
        }
        return reportList;
    }

    public static CertificateReport generateReport(org.bouncycastle.asn1.x509.Certificate cert) {
        CertificateReport report = new CertificateReport();
        setSubject(report, cert);
        setCommonNames(report, cert);
        setAlternativeNames(report, cert);
        setValidFrom(report, cert);
        setValidTo(report, cert);
        setPubkey(report, cert);
        setWeakDebianKey(report, cert);
        setIssuer(report, cert);
        setSignatureAndHashAlgorithm(report, cert);
        setExtendedValidation(report, cert);
        setCeritifcateTransparency(report, cert);
        setOcspMustStaple(report, cert);
        setCRLSupported(report, cert);
        setOcspSupported(report, cert);
        setRevoked(report, cert);
        setDnsCCA(report, cert);
        setSha256Hash(report, cert);
        report.setCertificate(cert);
        setVulnerableRoca(report, cert);
        TrustAnchorManager anchorManger = TrustAnchorManager.getInstance();
        report.setTrustAnchor(anchorManger.isTrustAnchor(report));
        if (report.getIssuer().equals(report.getSubject())) {
            report.setSelfSigned(true);
        } else {
            report.setSelfSigned(false);
        }
        return report;
    }

    private static void setSubject(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        X500Name x500name = cert.getSubject();
        if (x500name != null) {
            report.setSubject(x500name.toString());
        } else {
            report.setSubject("--not specified--");
        }
    }

    private static void setCommonNames(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
        StringBuilder commonNames = new StringBuilder();
        X500Name x500name = cert.getSubject();
        if (x500name != null) {
            RDN[] rdNs = x500name.getRDNs(BCStyle.CN);
            for (int i = 0; i < rdNs.length; i++) {
                commonNames.append(IETFUtils.valueToString(rdNs[i]));
                if (i < rdNs.length - 1) {
                    commonNames.append(" ,");
                }
            }
        }
        report.setCommonNames(commonNames.toString());
    }

    private static void setAlternativeNames(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {

    }

    private static void setValidFrom(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        if (cert.getStartDate() != null) {
            report.setValidFrom(cert.getStartDate().getDate());
        }
    }

    private static void setValidTo(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        if (cert.getEndDate() != null) {
            report.setValidTo(cert.getEndDate().getDate());
        }
    }

    private static void setPubkey(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        try {
            X509Certificate x509Cert = new X509CertificateObject(cert);
            if (x509Cert.getPublicKey() != null) {
                report.setPublicKey(x509Cert.getPublicKey());
            }
        } catch (CertificateParsingException ex) {
            LOGGER.error("Could not parse PublicKey from certificate", ex);
        }
    }

    private static void setWeakDebianKey(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setIssuer(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        if (cert.getIssuer() != null) {
            report.setIssuer(cert.getIssuer().toString());
        }
    }

    private static void setSignatureAndHashAlgorithm(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
        String sigAndHashString = null;
        try {
            X509CertificateObject x509Cert = new X509CertificateObject(cert);

            sigAndHashString = x509Cert.getSigAlgName();
            if (sigAndHashString != null) {
                String[] algos = sigAndHashString.toUpperCase().split("WITH");
                if (algos.length != 2) {
                    LOGGER.warn("Could not parse " + sigAndHashString + " into a reasonable SignatureAndHashAlgorithm");
                    return;
                }
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.valueOf(algos[1]);
                HashAlgorithm hashAlgorithm = HashAlgorithm.valueOf(algos[0]);
                if (hashAlgorithm == null) {
                    LOGGER.warn("Parsed an unknown HashAlgorithm");
                    return;
                }
                if (signatureAlgorithm == null) {
                    LOGGER.warn("Parsed an unknown SignatureAlgorithm");
                    return;
                }
                SignatureAndHashAlgorithm sigHashAlgo = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(signatureAlgorithm, hashAlgorithm);
                report.setSignatureAndHashAlgorithm(sigHashAlgo);
            }
        } catch (Exception E) {
            LOGGER.debug("Could not extraxt SignatureAndHashAlgorithm from String:" + sigAndHashString, E);
        }
    }

    private static void setExtendedValidation(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {

    }

    private static void setCeritifcateTransparency(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setOcspMustStaple(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setCRLSupported(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setOcspSupported(CertificateReport report,
            org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setRevoked(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setDnsCCA(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
    }

    private static void setSha256Hash(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        try {
            report.setSha256FingerprintHex(DatatypeConverter.printHexBinary(
                    MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())).toLowerCase());
        } catch (IOException | NoSuchAlgorithmException e) {
            LOGGER.warn("Could not create SHA-256 Hash", e);
        }
    }

    private static boolean rocaIsAvailable() {
        return false;
    }

    private static void setVulnerableRoca(CertificateReport report, org.bouncycastle.asn1.x509.Certificate cert) {
        if (report.getPublicKey() != null && report.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey pubkey = (RSAPublicKey) report.getPublicKey();
            report.setRocaVulnerable(BrokenKey.isAffected(pubkey));
        } else {
            report.setRocaVulnerable(false);
        }
    }
}
