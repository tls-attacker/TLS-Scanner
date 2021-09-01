/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAndHashAlgorithmsCertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SignatureAndHashAlgorithmsCertificateGuidelineCheck extends GuidelineCheck {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;

    private SignatureAndHashAlgorithmsCertificateGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm algorithm : report.getSupportedSignatureAndHashAlgorithmsCert()) {
            if (!this.recommendedAlgorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        return new SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(TestResult.of(nonRecommended.isEmpty()),
            nonRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAndHashAlgorithmsCert_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }

    public void setRecommendedAlgorithms(List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        this.recommendedAlgorithms = recommendedAlgorithms;
    }
}
