/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeyUsageCertificateCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Checks the key usage extension in the certificate.
 * <p>
 * RSA signature certificates, ECDSA signature certificates, or DSA signature certificates should have the
 * digitalSignature key usage.
 * <p>
 * ECDH certificates, DH certificates should have the keyAgreement key usage.
 */
public class KeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private final static List<SignatureAlgorithm> SIGNATURE_ALGORITHM_LIST =
        Arrays.asList(SignatureAlgorithm.RSA, SignatureAlgorithm.ECDSA, SignatureAlgorithm.DSA);

    private KeyUsageCertificateCheck() {
        super(null, null);
    }

    public KeyUsageCertificateCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public KeyUsageCertificateCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public KeyUsageCertificateCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        Extensions extensions = report.convertToCertificateHolder().getExtensions();
        if (extensions == null) {
            return new KeyUsageCertificateCheckResult(TestResult.FALSE, false, null);
        }
        KeyUsage extension = KeyUsage.fromExtensions(extensions);
        if (extension == null) {
            return new KeyUsageCertificateCheckResult(TestResult.FALSE, false, null);
        }
        if (SIGNATURE_ALGORITHM_LIST.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            if (!extension.hasUsages(KeyUsage.digitalSignature)) {
                return new KeyUsageCertificateCheckResult(TestResult.FALSE, false, "digitalSignature");
            }
        }
        if (report.getPublicKey() instanceof CustomDhPublicKey) {
            if (!extension.hasUsages(KeyUsage.keyAgreement)) {
                return new KeyUsageCertificateCheckResult(TestResult.FALSE, false, "keyAgreement");
            }
        }
        return new KeyUsageCertificateCheckResult(TestResult.TRUE, true, null);
    }

    @Override
    public String getId() {
        return "KeyUsageCertificate_" + getRequirementLevel();
    }

}
