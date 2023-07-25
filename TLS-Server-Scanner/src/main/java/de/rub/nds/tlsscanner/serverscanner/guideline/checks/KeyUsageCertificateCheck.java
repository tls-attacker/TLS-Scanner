/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import java.util.Arrays;
import java.util.List;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeyUsageCertificateCheckResult;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Checks the key usage extension in the certificate.
 *
 * <p>
 * RSA signature certificates, ECDSA signature certificates, or DSA signature
 * certificates should
 * have the digitalSignature key usage.
 *
 * <p>
 * ECDH certificates, DH certificates should have the keyAgreement key usage.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private static final List<SignatureAlgorithm> SIGNATURE_ALGORITHM_LIST = Arrays.asList(SignatureAlgorithm.RSA_PKCS1,
            SignatureAlgorithm.RSA_PSS, SignatureAlgorithm.ECDSA, SignatureAlgorithm.DSA);

    private KeyUsageCertificateCheck() {
        super(null, null);
    }

    public KeyUsageCertificateCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public KeyUsageCertificateCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public KeyUsageCertificateCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        List<X509ExtensionType> extensions = report.getSupportedExtensionTypes();
        if (extensions == null) {
            return new KeyUsageCertificateCheckResult(TestResults.FALSE, false, null);
        }
        for (X509ExtensionType extension : extensions) {
            if (extension == X509ExtensionType.KEY_USAGE) {
                return new KeyUsageCertificateCheckResult(TestResults.FALSE, false, null);
            }
        }
        if (report.getKeyUsageSet() != null) {
            if (report.getKeyUsageSet().contains(KeyUsage.DIGITAL_SIGNATURE)) {
                return new KeyUsageCertificateCheckResult(
                        TestResults.FALSE, false, "digitalSignature");
            }
        }
        if (report.getPublicKey() instanceof DhPublicKey) {
            if (!report.getKeyUsageSet().contains(KeyUsage.KEY_AGREEMENT)) {
                return new KeyUsageCertificateCheckResult(TestResults.FALSE, false, "keyAgreement");
            }
        }
        return new KeyUsageCertificateCheckResult(TestResults.TRUE, true, null);
    }

    @Override
    public String getId() {
        return "KeyUsageCertificate_" + getRequirementLevel();
    }
}
