/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateSignatureCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import java.util.Locale;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Checks if the certificate is signed with an algorithm consistent with the public key.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
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
                    TestResults.of(signatureAlgorithm.equals(SignatureAlgorithm.ECDSA)), keyAlgorithm,
                    signatureAlgorithm);
            case "DH":
                return new CertificateSignatureCheckResult(
                    TestResults.of(signatureAlgorithm.equals(SignatureAlgorithm.DSA)), keyAlgorithm, signatureAlgorithm);
            case "RSA":
            case "DSA":
                return new CertificateSignatureCheckResult(
                    TestResults.of(signatureAlgorithm.equals(SignatureAlgorithm.valueOf(keyAlgorithm))), keyAlgorithm,
                    signatureAlgorithm);
        }
        return new CertificateSignatureCheckResult(TestResults.UNCERTAIN, keyAlgorithm, signatureAlgorithm);
    }

    @Override
    public String getId() {
        return "SignatureCertificate_" + getRequirementLevel();
    }

}
