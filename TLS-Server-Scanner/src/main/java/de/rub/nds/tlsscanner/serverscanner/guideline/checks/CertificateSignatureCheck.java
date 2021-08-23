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
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateSignatureCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.Locale;

public class CertificateSignatureCheck extends CertificateGuidelineCheck {

    private CertificateSignatureCheck() {
        super(null, null);
    }

    public CertificateSignatureCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CertificateSignatureCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public CertificateSignatureCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        SignatureAlgorithm signatureAlgorithm = report.getSignatureAndHashAlgorithm().getSignatureAlgorithm();
        String keyAlgorithm = report.getPublicKey().getAlgorithm().toUpperCase(Locale.ENGLISH);
        switch (keyAlgorithm) {
            case "EC":
                return new CertificateSignatureCheckResult(
                    TestResult.of(signatureAlgorithm.equals(SignatureAlgorithm.ECDSA)), keyAlgorithm,
                    signatureAlgorithm);
            case "DH":
                return new CertificateSignatureCheckResult(
                    TestResult.of(signatureAlgorithm.equals(SignatureAlgorithm.DSA)), keyAlgorithm, signatureAlgorithm);
            case "RSA":
            case "DSA":
                return new CertificateSignatureCheckResult(
                    TestResult.of(signatureAlgorithm.equals(SignatureAlgorithm.valueOf(keyAlgorithm))), keyAlgorithm,
                    signatureAlgorithm);
        }
        return new CertificateSignatureCheckResult(TestResult.UNCERTAIN, keyAlgorithm, signatureAlgorithm);
    }

    @Override
    public String getId() {
        return "SignatureCertificate_" + getRequirementLevel();
    }

}
