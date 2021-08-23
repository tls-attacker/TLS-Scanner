/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeyUsageCertificateCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.Arrays;
import java.util.List;

public class KeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private final static List<SignatureAlgorithm> DIGITAL_SIGNATURE =
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
            return new KeyUsageCertificateCheckResult(TestResult.FALSE, null);
        }
        KeyUsage extension = KeyUsage.fromExtensions(extensions);
        if (extension == null) {
            return new KeyUsageCertificateCheckResult(TestResult.FALSE, null);
        }
        if (DIGITAL_SIGNATURE.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            if (!extension.hasUsages(KeyUsage.digitalSignature)) {
                return new KeyUsageCertificateCheckResult(TestResult.FALSE, "digitalSignature");
            }
        }
        if (report.getPublicKey() instanceof CustomDhPublicKey) {
            // TODO only for ECDH certificate, DH certificate
            if (!extension.hasUsages(KeyUsage.keyAgreement)) {
                return new KeyUsageCertificateCheckResult(TestResult.FALSE, "keyAgreement");
            }
        }
        return new KeyUsageCertificateCheckResult(TestResult.TRUE, null);
    }

    @Override
    public String getId() {
        return "KeyUsageCertificate_" + getRequirementLevel();
    }

}
