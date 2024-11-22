/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import de.rub.nds.asn1.oid.ObjectIdentifier;
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
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.joda.time.DateTime;
import org.joda.time.Duration;

public class CertificateReport {

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

    public CertificateReport() {}

    public X509NamedCurve getNamedCurve() {
        return namedCurve;
    }

    public void setNamedCurve(X509NamedCurve namedCurve) {
        this.namedCurve = namedCurve;
    }

    public X509SignatureAlgorithm getX509SignatureAlgorithm() {
        return x509SignatureAlgorithm;
    }

    public void setX509SignatureAlgorithm(X509SignatureAlgorithm x509SignatureAlgorithm) {
        this.x509SignatureAlgorithm = x509SignatureAlgorithm;
    }

    public Duration getRemainingDuration() {
        return remainingDuration;
    }

    public void setRemainingDuration(Duration remainingDuration) {
        this.remainingDuration = remainingDuration;
    }

    public Duration getOriginalFullDuration() {
        return originalFullDuration;
    }

    public void setOriginalFullDuration(Duration originalFullDuration) {
        this.originalFullDuration = originalFullDuration;
    }

    public Set<KeyUsage> getKeyUsageSet() {
        return keyUsageSet;
    }

    public void setKeyUsageSet(Set<KeyUsage> keyUsageSet) {
        this.keyUsageSet = keyUsageSet;
    }

    public List<X509ExtensionType> getSupportedExtensionTypes() {
        return supportedExtensionTypes;
    }

    public void setSupportedExtensionTypes(List<X509ExtensionType> supportedExtensionTypes) {
        this.supportedExtensionTypes = supportedExtensionTypes;
    }

    public X509Version getVersion() {
        return version;
    }

    public void setVersion(X509Version version) {
        this.version = version;
    }

    public ObjectIdentifier getSignatureAndHashAlgorithmOid() {
        return signatureAndHashAlgorithmOid;
    }

    public void setSignatureAndHashAlgorithmOid(ObjectIdentifier signatureAndHashAlgorithmOid) {
        this.signatureAndHashAlgorithmOid = signatureAndHashAlgorithmOid;
    }

    public Boolean getExtendedKeyUsagePresent() {
        return extendedKeyUsagePresent;
    }

    public void setExtendedKeyUsagePresent(Boolean extendedKeyUsagePresent) {
        this.extendedKeyUsagePresent = extendedKeyUsagePresent;
    }

    public Boolean getExtendedKeyUsageServerAuth() {
        return extendedKeyUsageServerAuth;
    }

    public void setExtendedKeyUsageServerAuth(Boolean extendedKeyUsageServerAuth) {
        this.extendedKeyUsageServerAuth = extendedKeyUsageServerAuth;
    }

    public byte[] getSHA256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(byte[] sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public String getSubject() {
        return subject;
    }

    public String getCommonName() {
        return commonName;
    }

    public List<String> getAlternativeNames() {
        return alternativeNames;
    }

    public DateTime getNotBefore() {
        return notBefore;
    }

    public DateTime getNotAfter() {
        return notAfter;
    }

    public PublicKeyContainer getPublicKey() {
        return publicKey;
    }

    public Boolean getWeakDebianKey() {
        return weakDebianKey;
    }

    public String getIssuer() {
        return issuer;
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

    public void setCommonName(String commonNames) {
        this.commonName = commonNames;
    }

    public void setAlternativeNames(List<String> alternativeNames) {
        this.alternativeNames = alternativeNames;
    }

    public void setNotBefore(DateTime notBefore) {
        this.notBefore = notBefore;
    }

    public void setNotAfter(DateTime notAfter) {
        this.notAfter = notAfter;
    }

    public void setPublicKey(PublicKeyContainer publicKey) {
        this.publicKey = publicKey;
    }

    public void setWeakDebianKey(Boolean weakDebianKey) {
        this.weakDebianKey = weakDebianKey;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
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

    public void setCustomTrustAnchor(Boolean customTrustAnchor) {
        this.customTrustAnchor = customTrustAnchor;
    }

    public Boolean isCustomTrustAnchor() {
        return customTrustAnchor;
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
                || !Objects.equals(sha256Fingerprint, otherReport.getSHA256Fingerprint())
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
        hash = 71 * hash + Objects.hashCode(this.sha256Fingerprint);
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
