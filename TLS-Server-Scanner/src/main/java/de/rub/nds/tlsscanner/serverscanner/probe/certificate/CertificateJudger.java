/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.certificate;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x509.Certificate;
import sun.security.x509.X509CertImpl;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateJudger {

    private final Certificate certificate;
    private final String domainName;
    private final CertificateReport report;

    public CertificateJudger(Certificate certificate, CertificateReport report, String domainName) {
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
        if (report.getSignatureAndHashAlgorithm() != null) {
            HashAlgorithm algo = report.getSignatureAndHashAlgorithm().getHashAlgorithm();
            return algo == HashAlgorithm.MD5 || algo == HashAlgorithm.NONE || algo == HashAlgorithm.SHA1;
        } else {
            return null;
        }
    }

    public Boolean isWeakSigAlgo(CertificateReport report) {
        if (report.getSignatureAndHashAlgorithm() != null) {
            SignatureAlgorithm algo = report.getSignatureAndHashAlgorithm().getSignatureAlgorithm();
            return algo == SignatureAlgorithm.ANONYMOUS; // TODO is this weak?
        } else {
            return null;
        }
    }

    public Boolean isWeakKey(CertificateReport report) {
        return report.getWeakDebianKey() == Boolean.TRUE;
    }

    public Boolean isCertificateExpired(CertificateReport report) {
        if (report.getValidTo() != null) {
            return !report.getValidTo().after(new Date(System.currentTimeMillis()));
        } else {
            return null;
        }
    }

    public Boolean isCertificateValidYet(CertificateReport report) {
        if (report.getValidFrom() != null) {
            return !report.getValidFrom().before(new Date(System.currentTimeMillis()));
        } else {
            return null;
        }
    }

    public Boolean isRevoked(Certificate certificate) {
        // TODO
        return false;
    }

    public Boolean domainNameDoesNotMatch(Certificate certificate, String domainName) {
        // TODO
        return false;
    }

    private Boolean isNotTrusted(Certificate certificate) {
        // TODO
        return false;
    }

    private Boolean isSelfSigned(Certificate certificate) {
        return false;

    }

    private Boolean checkDomainNameMatch() {
        // if (domainNameDoesNotMatch(certificate, domainName)) {
        // tlsCheckList.add(new ConfigurationFlaw("Domain nicht zulässig",
        // FlawLevel.FATAL,
        // "Das eingesetzte Zertifikat ist für die gescannte Domain nicht gültig.",
        // "Beantrage sie ein neues Zertifikat welches ebenfalls für die Domain "
        // + domainName
        // + " gültig ist."));
        // }
        return null;
    }

    private Boolean checkCertificateTrusted() {
        // if (isNotTrusted(certificate)) {
        // tlsCheckList.add(new
        // ConfigurationFlaw("Zertifikat nicht vertrauenswürdig",
        // FlawLevel.FATAL,
        // "Dem Eingesetzten Zertifikat wird nicht vertraut",
        // "Beantrage sie ein neues Zertifikat welchem Vertraut werden kann."));
        // }
        return null;
    }

    public Boolean isSelfSigned() {
        try {
            // Try to verify certificate signature with its own public key
            X509Certificate cert = new X509CertImpl(certificate.getEncoded());
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            return true;
        } catch (SignatureException | InvalidKeyException ex) {
            return false;
        } catch (Exception E) {
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
