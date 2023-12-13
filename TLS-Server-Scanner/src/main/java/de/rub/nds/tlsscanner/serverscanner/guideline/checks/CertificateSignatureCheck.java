/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateSignatureCheckResult;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Checks if the certificate is signed with an algorithm consistent with the public key. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateSignatureCheck extends CertificateGuidelineCheck {

    private CertificateSignatureCheck() {
        super(null, null);
    }

    public CertificateSignatureCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CertificateSignatureCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public CertificateSignatureCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        CertificateReport report = chain.getLeafReport();
        SignatureAlgorithm signatureAlgorithm = report.getSignatureAlgorithm();
        PublicKeyContainer publicKey = report.getPublicKey();
        X509PublicKeyType publicKeyType;
        if (publicKey instanceof EcdsaPublicKey) {
            return new CertificateSignatureCheckResult(
                    getName(),
                    GuidelineAdherence.of(signatureAlgorithm.equals(SignatureAlgorithm.ECDSA)),
                    X509PublicKeyType.ECDH_ECDSA,
                    signatureAlgorithm);
        }
        if (publicKey instanceof DhPublicKey) {
            return new CertificateSignatureCheckResult(
                    getName(),
                    GuidelineAdherence.of(signatureAlgorithm.equals(SignatureAlgorithm.DSA)),
                    X509PublicKeyType.DH,
                    signatureAlgorithm);
        }
        if (publicKey instanceof RsaPublicKey || publicKey instanceof DsaPublicKey) {

            if (publicKey instanceof RsaPublicKey) {
                publicKeyType = X509PublicKeyType.RSA;
            } else {
                publicKeyType = X509PublicKeyType.DSA;
            }
            return new CertificateSignatureCheckResult(
                    getName(),
                    GuidelineAdherence.of(
                            publicKeyType.canBeUsedWithSignatureAlgorithm(signatureAlgorithm)),
                    publicKeyType,
                    signatureAlgorithm);
        }
        return new CertificateSignatureCheckResult(
                getName(), GuidelineAdherence.CHECK_FAILED, null, signatureAlgorithm);
    }

    @Override
    public String toString() {
        return "SignatureCertificate_" + getRequirementLevel();
    }
}
