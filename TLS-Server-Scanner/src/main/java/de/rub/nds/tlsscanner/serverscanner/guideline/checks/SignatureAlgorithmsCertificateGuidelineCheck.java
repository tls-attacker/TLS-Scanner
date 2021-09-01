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
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SignatureAlgorithmsCertificateGuidelineCheck extends CertificateGuidelineCheck {

    private List<SignatureAlgorithm> recommendedAlgorithms;

    private SignatureAlgorithmsCertificateGuidelineCheck() {
        super(null, null);
    }

    public SignatureAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        boolean onlyOneCertificate, List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, onlyOneCertificate);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, boolean onlyOneCertificate, List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (report.getSignatureAndHashAlgorithm() == null) {
            return new SignatureAlgorithmsGuidelineCheckResult(TestResult.UNCERTAIN, null);
        }
        Set<SignatureAlgorithm> nonRecommended = new HashSet<>();
        if (!this.recommendedAlgorithms.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            nonRecommended.add(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm());
        }
        return new SignatureAlgorithmsGuidelineCheckResult(TestResult.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAlgorithmsCert_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
