/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.joda.time.DateTime;
import org.joda.time.Duration;

public class CertificateReport {

    @JsonIgnore private X509Certificate certificate;

    private X509Version version;
    private String subject;
    private String commonName;
    private List<String> alternativeNames;
    private DateTime notBefore;
    private DateTime notAfter;
    private Duration remainingDuration;
    private Duration originalFullDuration;
    private PublicKeyContainer publicKey;
    private Boolean weakDebianKey;
    private String issuer;
    private X509PublicKeyType publicKeyType;
    private X509SignatureAlgorithm x509SignatureAlgorithm;
    private SignatureAlgorithm signatureAlgorithm;
    private X509NamedCurve namedCurve;
    private HashAlgorithm hashAlgorithm;
    private Boolean extendedValidation;
    private Boolean certificateTransparency;
    private Boolean ocspMustStaple;
    private Boolean crlSupported;
    private Boolean ocspSupported;
    private Boolean revoked;
    private Boolean dnsCAA;
    private Boolean trusted;
    private byte[] sha256Fingerprint;
    private Boolean rocaVulnerable;
    private Boolean trustAnchor;
    private Boolean customTrustAnchor;
    private Boolean selfSigned;
    private Boolean leafCertificate;
    private Boolean extendedKeyUsageServerAuth;
    private Boolean extendedKeyUsagePresent;
    private String sha256Pin;
    private ObjectIdentifier signatureAndHashAlgorithmOid;
    private List<X509ExtensionType> supportedExtensionTypes;
    private Set<KeyUsage> keyUsageSet;

    /** Default constructor for CertificateReport. */
    public CertificateReport() {}

    /**
     * Gets the public key type of the certificate.
     *
     * @return the X509 public key type
     */
    public X509PublicKeyType getPublicKeyType() {
        return publicKeyType;
    }

    /**
     * Sets the public key type of the certificate.
     *
     * @param publicKeyType the X509 public key type to set
     */
    public void setPublicKeyType(X509PublicKeyType publicKeyType) {
        this.publicKeyType = publicKeyType;
    }

    /**
     * Gets the X509 certificate object.
     *
     * @return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the X509 certificate object.
     *
     * @param certificate the X509 certificate to set
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the named curve used in elliptic curve cryptography.
     *
     * @return the X509 named curve
     */
    public X509NamedCurve getNamedCurve() {
        return namedCurve;
    }

    /**
     * Sets the named curve used in elliptic curve cryptography.
     *
     * @param namedCurve the X509 named curve to set
     */
    public void setNamedCurve(X509NamedCurve namedCurve) {
        this.namedCurve = namedCurve;
    }

    /**
     * Gets the X509 signature algorithm used by the certificate.
     *
     * @return the X509 signature algorithm
     */
    public X509SignatureAlgorithm getX509SignatureAlgorithm() {
        return x509SignatureAlgorithm;
    }

    /**
     * Sets the X509 signature algorithm used by the certificate.
     *
     * @param x509SignatureAlgorithm the X509 signature algorithm to set
     */
    public void setX509SignatureAlgorithm(X509SignatureAlgorithm x509SignatureAlgorithm) {
        this.x509SignatureAlgorithm = x509SignatureAlgorithm;
    }

    /**
     * Gets the remaining duration until the certificate expires.
     *
     * @return the remaining duration
     */
    public Duration getRemainingDuration() {
        return remainingDuration;
    }

    /**
     * Sets the remaining duration until the certificate expires.
     *
     * @param remainingDuration the remaining duration to set
     */
    public void setRemainingDuration(Duration remainingDuration) {
        this.remainingDuration = remainingDuration;
    }

    /**
     * Gets the original full duration of the certificate validity period.
     *
     * @return the original full duration
     */
    public Duration getOriginalFullDuration() {
        return originalFullDuration;
    }

    /**
     * Sets the original full duration of the certificate validity period.
     *
     * @param originalFullDuration the original full duration to set
     */
    public void setOriginalFullDuration(Duration originalFullDuration) {
        this.originalFullDuration = originalFullDuration;
    }

    /**
     * Gets the set of key usage flags defined in the certificate.
     *
     * @return the set of key usage flags
     */
    public Set<KeyUsage> getKeyUsageSet() {
        return keyUsageSet;
    }

    /**
     * Sets the key usage flags for the certificate.
     *
     * @param keyUsageSet the set of key usage flags to set
     */
    public void setKeyUsageSet(Set<KeyUsage> keyUsageSet) {
        this.keyUsageSet = keyUsageSet;
    }

    /**
     * Gets the list of X509 extension types supported by the certificate.
     *
     * @return the list of supported extension types
     */
    public List<X509ExtensionType> getSupportedExtensionTypes() {
        return supportedExtensionTypes;
    }

    /**
     * Sets the list of X509 extension types supported by the certificate.
     *
     * @param supportedExtensionTypes the list of supported extension types to set
     */
    public void setSupportedExtensionTypes(List<X509ExtensionType> supportedExtensionTypes) {
        this.supportedExtensionTypes = supportedExtensionTypes;
    }

    /**
     * Gets the X509 version of the certificate.
     *
     * @return the X509 version
     */
    public X509Version getVersion() {
        return version;
    }

    /**
     * Sets the X509 version of the certificate.
     *
     * @param version the X509 version to set
     */
    public void setVersion(X509Version version) {
        this.version = version;
    }

    /**
     * Gets the object identifier for the signature and hash algorithm.
     *
     * @return the signature and hash algorithm OID
     */
    public ObjectIdentifier getSignatureAndHashAlgorithmOid() {
        return signatureAndHashAlgorithmOid;
    }

    /**
     * Sets the object identifier for the signature and hash algorithm.
     *
     * @param signatureAndHashAlgorithmOid the signature and hash algorithm OID to set
     */
    public void setSignatureAndHashAlgorithmOid(ObjectIdentifier signatureAndHashAlgorithmOid) {
        this.signatureAndHashAlgorithmOid = signatureAndHashAlgorithmOid;
    }

    /**
     * Checks if the extended key usage extension is present in the certificate.
     *
     * @return true if extended key usage is present, false otherwise, or null if not checked
     */
    public Boolean getExtendedKeyUsagePresent() {
        return extendedKeyUsagePresent;
    }

    /**
     * Sets whether the extended key usage extension is present in the certificate.
     *
     * @param extendedKeyUsagePresent true if extended key usage is present, false otherwise
     */
    public void setExtendedKeyUsagePresent(Boolean extendedKeyUsagePresent) {
        this.extendedKeyUsagePresent = extendedKeyUsagePresent;
    }

    /**
     * Checks if the certificate has server authentication in its extended key usage.
     *
     * @return true if server authentication is present, false otherwise, or null if not checked
     */
    public Boolean getExtendedKeyUsageServerAuth() {
        return extendedKeyUsageServerAuth;
    }

    /**
     * Sets whether the certificate has server authentication in its extended key usage.
     *
     * @param extendedKeyUsageServerAuth true if server authentication is present, false otherwise
     */
    public void setExtendedKeyUsageServerAuth(Boolean extendedKeyUsageServerAuth) {
        this.extendedKeyUsageServerAuth = extendedKeyUsageServerAuth;
    }

    /**
     * Gets the SHA-256 fingerprint of the certificate.
     *
     * @return the SHA-256 fingerprint as a byte array
     */
    public byte[] getSHA256Fingerprint() {
        return sha256Fingerprint;
    }

    /**
     * Sets the SHA-256 fingerprint of the certificate.
     *
     * @param sha256Fingerprint the SHA-256 fingerprint as a byte array
     */
    public void setSha256Fingerprint(byte[] sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    /**
     * Gets the subject distinguished name of the certificate.
     *
     * @return the subject DN string
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Gets the common name (CN) from the certificate subject.
     *
     * @return the common name
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Gets the list of subject alternative names from the certificate.
     *
     * @return the list of alternative names
     */
    public List<String> getAlternativeNames() {
        return alternativeNames;
    }

    /**
     * Gets the start date of the certificate validity period.
     *
     * @return the not-before date
     */
    public DateTime getNotBefore() {
        return notBefore;
    }

    /**
     * Gets the end date of the certificate validity period.
     *
     * @return the not-after date
     */
    public DateTime getNotAfter() {
        return notAfter;
    }

    /**
     * Gets the public key container from the certificate.
     *
     * @return the public key container
     */
    public PublicKeyContainer getPublicKey() {
        return publicKey;
    }

    /**
     * Checks if the certificate uses a weak Debian key.
     *
     * @return true if using weak Debian key, false otherwise, or null if not checked
     */
    public Boolean getWeakDebianKey() {
        return weakDebianKey;
    }

    /**
     * Gets the issuer distinguished name of the certificate.
     *
     * @return the issuer DN string
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Checks if the certificate is an Extended Validation (EV) certificate.
     *
     * @return true if EV certificate, false otherwise, or null if not checked
     */
    public Boolean getExtendedValidation() {
        return extendedValidation;
    }

    /**
     * Checks if the certificate supports Certificate Transparency.
     *
     * @return true if CT is supported, false otherwise, or null if not checked
     */
    public Boolean getCertificateTransparency() {
        return certificateTransparency;
    }

    /**
     * Checks if the certificate has the OCSP must-staple extension.
     *
     * @return true if OCSP must-staple is required, false otherwise, or null if not checked
     */
    public Boolean getOcspMustStaple() {
        return ocspMustStaple;
    }

    /**
     * Checks if the certificate supports Certificate Revocation List (CRL).
     *
     * @return true if CRL is supported, false otherwise, or null if not checked
     */
    public Boolean getCrlSupported() {
        return crlSupported;
    }

    /**
     * Checks if the certificate supports Online Certificate Status Protocol (OCSP).
     *
     * @return true if OCSP is supported, false otherwise, or null if not checked
     */
    public Boolean getOcspSupported() {
        return ocspSupported;
    }

    /**
     * Checks if the certificate has been revoked.
     *
     * @return true if revoked, false otherwise, or null if not checked
     */
    public Boolean getRevoked() {
        return revoked;
    }

    /**
     * Checks if the certificate has DNS Certification Authority Authorization (CAA) records.
     *
     * @return true if DNS CAA is present, false otherwise, or null if not checked
     */
    public Boolean getDnsCAA() {
        return dnsCAA;
    }

    /**
     * Checks if the certificate is trusted by the system trust store.
     *
     * @return true if trusted, false otherwise, or null if not checked
     */
    public Boolean getTrusted() {
        return trusted;
    }

    /**
     * Sets the subject distinguished name of the certificate.
     *
     * @param subject the subject DN string to set
     */
    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     * Sets the common name (CN) from the certificate subject.
     *
     * @param commonNames the common name to set
     */
    public void setCommonName(String commonNames) {
        this.commonName = commonNames;
    }

    /**
     * Sets the list of subject alternative names for the certificate.
     *
     * @param alternativeNames the list of alternative names to set
     */
    public void setAlternativeNames(List<String> alternativeNames) {
        this.alternativeNames = alternativeNames;
    }

    /**
     * Sets the start date of the certificate validity period.
     *
     * @param notBefore the not-before date to set
     */
    public void setNotBefore(DateTime notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * Sets the end date of the certificate validity period.
     *
     * @param notAfter the not-after date to set
     */
    public void setNotAfter(DateTime notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * Sets the public key container for the certificate.
     *
     * @param publicKey the public key container to set
     */
    public void setPublicKey(PublicKeyContainer publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Sets whether the certificate uses a weak Debian key.
     *
     * @param weakDebianKey true if using weak Debian key, false otherwise
     */
    public void setWeakDebianKey(Boolean weakDebianKey) {
        this.weakDebianKey = weakDebianKey;
    }

    /**
     * Sets the issuer distinguished name of the certificate.
     *
     * @param issuer the issuer DN string to set
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Gets the signature algorithm used by the certificate.
     *
     * @return the signature algorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Sets the signature algorithm used by the certificate.
     *
     * @param signatureAlgorithm the signature algorithm to set
     */
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Gets the hash algorithm used by the certificate.
     *
     * @return the hash algorithm
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets the hash algorithm used by the certificate.
     *
     * @param hashAlgorithm the hash algorithm to set
     */
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Sets whether the certificate is an Extended Validation (EV) certificate.
     *
     * @param extendedValidation true if EV certificate, false otherwise
     */
    public void setExtendedValidation(Boolean extendedValidation) {
        this.extendedValidation = extendedValidation;
    }

    /**
     * Sets whether the certificate supports Certificate Transparency.
     *
     * @param certificateTransparency true if CT is supported, false otherwise
     */
    public void setCertificateTransparency(Boolean certificateTransparency) {
        this.certificateTransparency = certificateTransparency;
    }

    /**
     * Sets whether the certificate has the OCSP must-staple extension.
     *
     * @param ocspMustStaple true if OCSP must-staple is required, false otherwise
     */
    public void setOcspMustStaple(Boolean ocspMustStaple) {
        this.ocspMustStaple = ocspMustStaple;
    }

    /**
     * Sets whether the certificate supports Certificate Revocation List (CRL).
     *
     * @param crlSupported true if CRL is supported, false otherwise
     */
    public void setCrlSupported(Boolean crlSupported) {
        this.crlSupported = crlSupported;
    }

    /**
     * Sets whether the certificate supports Online Certificate Status Protocol (OCSP).
     *
     * @param ocspSupported true if OCSP is supported, false otherwise
     */
    public void setOcspSupported(Boolean ocspSupported) {
        this.ocspSupported = ocspSupported;
    }

    /**
     * Sets whether the certificate has been revoked.
     *
     * @param revoked true if revoked, false otherwise
     */
    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    /**
     * Sets whether the certificate has DNS Certification Authority Authorization (CAA) records.
     *
     * @param dnsCAA true if DNS CAA is present, false otherwise
     */
    public void setDnsCAA(Boolean dnsCAA) {
        this.dnsCAA = dnsCAA;
    }

    /**
     * Sets whether the certificate is trusted by the system trust store.
     *
     * @param trusted true if trusted, false otherwise
     */
    public void setTrusted(Boolean trusted) {
        this.trusted = trusted;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Fingerprint: ")
                .append(
                        sha256Fingerprint != null
                                ? DataConverter.bytesToHexString(sha256Fingerprint)
                                : "null")
                .append("\n");
        if (subject != null) {
            builder.append("Subject: ").append(subject).append("\n");
        }
        if (commonName != null) {
            builder.append("CommonNames: ").append(commonName).append("\n");
        }
        if (alternativeNames != null) {
            builder.append("AltNames   : ").append(alternativeNames).append("\n");
        }
        if (notBefore != null) {
            builder.append("Valid From : ").append(notBefore.toString()).append("\n");
        }
        if (notAfter != null) {
            builder.append("Valid Till : ").append(notAfter.toString()).append("\n");
        }
        if (publicKey != null) {
            builder.append("PublicKey  : ").append(printPublicKey(publicKey)).append("\n");
        }
        if (weakDebianKey != null) {
            builder.append("Weak Debian Key: ").append(weakDebianKey).append("\n");
        }
        if (issuer != null) {
            builder.append("Issuer\t\t   : ").append(issuer).append("\n");
        }
        if (signatureAlgorithm != null) {
            builder.append("Signature Algorithm: ")
                    .append(signatureAlgorithm.getHumanReadable())
                    .append("\n");
        }
        if (hashAlgorithm != null) {
            builder.append("Hash Algorithm     : ").append(hashAlgorithm.name()).append("\n");
        }
        if (extendedValidation != null) {
            builder.append("Extended Validation: ").append(extendedValidation).append("\n");
        }
        if (certificateTransparency != null) {
            builder.append("Certificate Transparency: ")
                    .append(certificateTransparency)
                    .append("\n");
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

    /**
     * Checks if the certificate is vulnerable to the ROCA vulnerability.
     *
     * @return true if ROCA vulnerable, false otherwise, or null if not checked
     */
    public Boolean getRocaVulnerable() {
        return rocaVulnerable;
    }

    /**
     * Sets whether the certificate is vulnerable to the ROCA vulnerability.
     *
     * @param rocaVulnerable true if ROCA vulnerable, false otherwise
     */
    public void setRocaVulnerable(Boolean rocaVulnerable) {
        this.rocaVulnerable = rocaVulnerable;
    }

    /**
     * Checks if the certificate is a trust anchor (root certificate).
     *
     * @return true if trust anchor, false otherwise, or null if not checked
     */
    public Boolean isTrustAnchor() {
        return trustAnchor;
    }

    /**
     * Sets whether the certificate is a trust anchor (root certificate).
     *
     * @param trustAnchor true if trust anchor, false otherwise
     */
    public void setTrustAnchor(Boolean trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    /**
     * Sets whether the certificate is a custom trust anchor.
     *
     * @param customTrustAnchor true if custom trust anchor, false otherwise
     */
    public void setCustomTrustAnchor(Boolean customTrustAnchor) {
        this.customTrustAnchor = customTrustAnchor;
    }

    /**
     * Checks if the certificate is a custom trust anchor.
     *
     * @return true if custom trust anchor, false otherwise, or null if not checked
     */
    public Boolean isCustomTrustAnchor() {
        return customTrustAnchor;
    }

    /**
     * Checks if this is a leaf certificate (end-entity certificate).
     *
     * @return true if leaf certificate, false otherwise, or null if not checked
     */
    public Boolean getLeafCertificate() {
        return leafCertificate;
    }

    /**
     * Sets whether this is a leaf certificate (end-entity certificate).
     *
     * @param leafCertificate true if leaf certificate, false otherwise
     */
    public void setLeafCertificate(Boolean leafCertificate) {
        this.leafCertificate = leafCertificate;
    }

    /**
     * Checks if the certificate is self-signed.
     *
     * @return true if self-signed, false otherwise, or null if not checked
     */
    public Boolean getSelfSigned() {
        return selfSigned;
    }

    /**
     * Sets whether the certificate is self-signed.
     *
     * @param selfSigned true if self-signed, false otherwise
     */
    public void setSelfSigned(Boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    /**
     * Gets the SHA-256 pin for HTTP Public Key Pinning (HPKP).
     *
     * @return the SHA-256 pin string
     */
    public String getSha256Pin() {
        return sha256Pin;
    }

    /**
     * Sets the SHA-256 pin for HTTP Public Key Pinning (HPKP).
     *
     * @param sha256Pin the SHA-256 pin string to set
     */
    public void setSha256Pin(String sha256Pin) {
        this.sha256Pin = sha256Pin;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        final CertificateReport otherReport = (CertificateReport) obj;
        if (!Objects.equals(subject, otherReport.getSubject())
                || !Objects.equals(commonName, otherReport.getCommonName())
                || !Objects.equals(alternativeNames, otherReport.getAlternativeNames())
                || !Objects.equals(notBefore, otherReport.getNotBefore())
                || !Objects.equals(notAfter, otherReport.getNotAfter())
                || !Objects.equals(publicKey, otherReport.getPublicKey())
                || !Objects.equals(weakDebianKey, otherReport.getWeakDebianKey())
                || !Objects.equals(issuer, otherReport.getIssuer())
                || !Objects.equals(signatureAlgorithm, otherReport.getSignatureAlgorithm())
                || !Objects.equals(hashAlgorithm, otherReport.getHashAlgorithm())
                || !Objects.equals(extendedValidation, otherReport.getExtendedValidation())
                || !Objects.equals(
                        certificateTransparency, otherReport.getCertificateTransparency())
                || !Objects.equals(ocspMustStaple, otherReport.getOcspMustStaple())
                || !Objects.equals(crlSupported, otherReport.getCrlSupported())
                || !Objects.equals(ocspSupported, otherReport.getOcspSupported())
                || !Objects.equals(revoked, otherReport.getRevoked())
                || !Objects.equals(dnsCAA, otherReport.getDnsCAA())
                || !Objects.equals(trusted, otherReport.getTrusted())
                || !Arrays.equals(sha256Fingerprint, otherReport.getSHA256Fingerprint())
                || !Objects.equals(rocaVulnerable, otherReport.getRocaVulnerable())
                || !Objects.equals(trustAnchor, otherReport.isTrustAnchor())
                || !Objects.equals(selfSigned, otherReport.getSelfSigned())
                || !Objects.equals(leafCertificate, otherReport.getLeafCertificate())
                || !Objects.equals(sha256Pin, otherReport.getSha256Pin())) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.subject);
        hash = 71 * hash + Objects.hashCode(this.commonName);
        hash = 71 * hash + Objects.hashCode(this.alternativeNames);
        hash = 71 * hash + Objects.hashCode(this.notBefore);
        hash = 71 * hash + Objects.hashCode(this.notAfter);
        hash = 71 * hash + Objects.hashCode(this.publicKey);
        hash = 71 * hash + Objects.hashCode(this.weakDebianKey);
        hash = 71 * hash + Objects.hashCode(this.issuer);
        hash = 71 * hash + Objects.hashCode(this.signatureAlgorithm);
        hash = 71 * hash + Objects.hashCode(this.hashAlgorithm);
        hash = 71 * hash + Objects.hashCode(this.extendedValidation);
        hash = 71 * hash + Objects.hashCode(this.certificateTransparency);
        hash = 71 * hash + Objects.hashCode(this.ocspMustStaple);
        hash = 71 * hash + Objects.hashCode(this.crlSupported);
        hash = 71 * hash + Objects.hashCode(this.ocspSupported);
        hash = 71 * hash + Objects.hashCode(this.revoked);
        hash = 71 * hash + Objects.hashCode(this.dnsCAA);
        hash = 71 * hash + Objects.hashCode(this.trusted);
        hash = 71 * hash + Arrays.hashCode(this.sha256Fingerprint);
        hash = 71 * hash + Objects.hashCode(this.rocaVulnerable);
        hash = 71 * hash + Objects.hashCode(this.trustAnchor);
        hash = 71 * hash + Objects.hashCode(this.selfSigned);
        hash = 71 * hash + Objects.hashCode(this.leafCertificate);
        hash = 71 * hash + Objects.hashCode(this.sha256Pin);
        return hash;
    }

    private String printPublicKey(PublicKeyContainer publicKey) {
        StringBuilder builder = new StringBuilder();
        if (publicKey instanceof DhPublicKey) {
            DhPublicKey dhPublicKey = (DhPublicKey) publicKey;
            builder.append("Static Diffie Hellman\n");
            appendHexString(builder, "Modulus", dhPublicKey.getModulus().toString(16));
            appendHexString(builder, "Generator", dhPublicKey.getModulus().toString(16));
            appendHexString(builder, "PublicKey", dhPublicKey.getPublicKey().toString(16));
        } else if (publicKey instanceof DsaPublicKey) {
            DsaPublicKey dsaPublicKey = (DsaPublicKey) publicKey;
            builder.append("DSA\n");
            appendHexString(builder, "Modulus", dsaPublicKey.getModulus().toString(16));
            appendHexString(builder, "Generator", dsaPublicKey.getGenerator().toString(16));
            appendHexString(builder, "Q", dsaPublicKey.getQ().toString(16));
            appendHexString(builder, "X", dsaPublicKey.getY().toString(16));
        } else if (publicKey instanceof RsaPublicKey) {
            RsaPublicKey rsaPublicKey = (RsaPublicKey) publicKey;
            builder.append("RSA\n");
            appendHexString(builder, "Modulus", rsaPublicKey.getModulus().toString(16));
            appendHexString(builder, "Generator", rsaPublicKey.getModulus().toString(16));
            appendHexString(
                    builder, "Public exponent", rsaPublicKey.getPublicExponent().toString(16));
        } else if (publicKey instanceof EcdhPublicKey) {
            EcdhPublicKey ecPublicKey = (EcdhPublicKey) publicKey;
            builder.append("ECDH\n");
            builder.append("\t Group:").append(ecPublicKey.getParameters().getName()).append("\n");
            builder.append("\t Public Point:")
                    .append(ecPublicKey.getPublicPoint().toString())
                    .append("\n");
        } else if (publicKey instanceof EcdsaPublicKey) {
            EcdsaPublicKey ecPublicKey = (EcdsaPublicKey) publicKey;
            builder.append("ECDSA\n");
            builder.append("\t Group:").append(ecPublicKey.getParameters().getName()).append("\n");
            builder.append("\t Public Point:")
                    .append(ecPublicKey.getPublicPoint().toString())
                    .append("\n");

        } else {
            builder.append(publicKey.toString()).append("\n");
        }
        return builder.toString();
    }

    private StringBuilder appendHexString(StringBuilder builder, String title, String value) {
        return builder.append("\t " + title + ":").append("0x" + value).append("\n");
    }
}
