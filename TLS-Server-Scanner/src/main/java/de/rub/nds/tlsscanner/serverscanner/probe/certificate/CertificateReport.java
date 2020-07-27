/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.certificate;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class CertificateReport {

    private final static Logger LOGGER = LogManager.getLogger();

    private String subject;
    private String commonNames;
    private String alternativenames;
    private Date validFrom;
    private Date validTo;
    private PublicKey publicKey;
    private Boolean weakDebianKey;
    private String issuer;
    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    private Boolean extendedValidation;
    private Boolean certificateTransparency;
    private Boolean ocspMustStaple;
    private Boolean crlSupported;
    private Boolean ocspSupported;
    private Boolean revoked;
    private Boolean dnsCAA;
    private Boolean trusted;
    private Certificate certificate;
    private String sha256Fingerprint;
    private Boolean rocaVulnerable;
    private Boolean trustAnchor;
    private Boolean selfSigned;
    private Boolean leafCertificate;
    private String sha256Pin;

    public CertificateReport() {
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public X509CertificateHolder convertToCertificateHolder() {
        return new X509CertificateHolder(certificate);
    }

    public X509Certificate convertToX509Certificate() {
        try {
            return new X509CertificateObject(certificate);
        } catch (CertificateParsingException ex) {
            LOGGER.error("Certificate Parsing Error", ex);
            return null;
        }
    }

    public String getSHA256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(String sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public String getSubject() {
        return subject;
    }

    public String getCommonNames() {
        return commonNames;
    }

    public String getAlternativenames() {
        return alternativenames;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Boolean getWeakDebianKey() {
        return weakDebianKey;
    }

    public String getIssuer() {
        return issuer;
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return signatureAndHashAlgorithm;
    }

    public Boolean getExtendedValidation() {
        return extendedValidation;
    }

    public Boolean getCertificateTransparency() {
        return certificateTransparency;
    }

    public Boolean getOcspMustStaple() {
        return ocspMustStaple;
    }

    public Boolean getCrlSupported() {
        return crlSupported;
    }

    public Boolean getOcspSupported() {
        return ocspSupported;
    }

    public Boolean getRevoked() {
        return revoked;
    }

    public Boolean getDnsCAA() {
        return dnsCAA;
    }

    public Boolean getTrusted() {
        return trusted;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setCommonNames(String commonNames) {
        this.commonNames = commonNames;
    }

    public void setAlternativenames(String alternativenames) {
        this.alternativenames = alternativenames;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setWeakDebianKey(Boolean weakDebianKey) {
        this.weakDebianKey = weakDebianKey;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public void setExtendedValidation(Boolean extendedValidation) {
        this.extendedValidation = extendedValidation;
    }

    public void setCertificateTransparency(Boolean certificateTransparency) {
        this.certificateTransparency = certificateTransparency;
    }

    public void setOcspMustStaple(Boolean ocspMustStaple) {
        this.ocspMustStaple = ocspMustStaple;
    }

    public void setCrlSupported(Boolean crlSupported) {
        this.crlSupported = crlSupported;
    }

    public void setOcspSupported(Boolean ocspSupported) {
        this.ocspSupported = ocspSupported;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public void setDnsCAA(Boolean dnsCAA) {
        this.dnsCAA = dnsCAA;
    }

    public void setTrusted(Boolean trusted) {
        this.trusted = trusted;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Fingerprint: ").append(sha256Fingerprint).append("\n");
        if (subject != null) {
            builder.append("Subject: ").append(subject).append("\n");
        }
        if (commonNames != null) {
            builder.append("CommonNames: ").append(commonNames).append("\n");
        }
        if (alternativenames != null) {
            builder.append("AltNames   : ").append(alternativenames).append("\n");
        }
        if (validFrom != null) {
            builder.append("Valid From : ").append(validFrom.toString()).append("\n");
        }
        if (validTo != null) {
            builder.append("Valid Till : ").append(validTo.toString()).append("\n");
        }
        if (publicKey != null) {
            builder.append("PublicKey  : ").append(publicKey.toString()).append("\n");
        }
        if (weakDebianKey != null) {
            builder.append("Weak Debian Key: ").append(weakDebianKey).append("\n");
        }
        if (issuer != null) {
            builder.append("Issuer\t\t   : ").append(issuer).append("\n");
        }
        if (signatureAndHashAlgorithm != null) {
            builder.append("Signature Algorithm: ").append(signatureAndHashAlgorithm.getSignatureAlgorithm().name())
                    .append("\n");
        }
        if (signatureAndHashAlgorithm != null) {
            builder.append("Hash Algorithm     : ").append(signatureAndHashAlgorithm.getHashAlgorithm().name())
                    .append("\n");
        }
        if (extendedValidation != null) {
            builder.append("Extended Validation: ").append(extendedValidation).append("\n");
        }
        if (certificateTransparency != null) {
            builder.append("Certificate Transparency: ").append(certificateTransparency).append("\n");
        }
        if (ocspMustStaple != null) {
            builder.append("OCSP must Staple   : ").append(ocspMustStaple).append("\n");
        }
        if (crlSupported != null) {
            builder.append("CRL Supported: ").append(crlSupported).append("\n");
        }
        if (ocspSupported != null) {
            builder.append("OCSP Supported: ").append(ocspSupported).append("\n");
        }
        if (revoked != null) {
            builder.append("Is Revoked: ").append(revoked).append("\n");
        }
        if (dnsCAA != null) {
            builder.append("DNS CCA: ").append(dnsCAA).append("\n");
        }
        if (trusted != null) {
            builder.append("Trusted: ").append(trusted).append("\n");
        }
        if (rocaVulnerable != null) {
            builder.append("ROCA (simple): ").append(rocaVulnerable).append("\n");
        } else {
            builder.append("ROCA (simple): not tested");
        }
        return builder.toString();
    }

    public Boolean getRocaVulnerable() {
        return rocaVulnerable;
    }

    public void setRocaVulnerable(Boolean rocaVulnerable) {
        this.rocaVulnerable = rocaVulnerable;
    }

    public Boolean isTrustAnchor() {
        return trustAnchor;
    }

    public void setTrustAnchor(Boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    public Boolean getLeafCertificate() {
        return leafCertificate;
    }

    public void setLeafCertificate(Boolean leafCertificate) {
        this.leafCertificate = leafCertificate;
    }

    public Boolean getSelfSigned() {
        return selfSigned;
    }

    public void setSelfSigned(Boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    public String getSha256Pin() {
        return sha256Pin;
    }

    public void setSha256Pin(String sha256Pin) {
        this.sha256Pin = sha256Pin;
    }
}
