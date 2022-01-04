/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.HashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HashAlgorithmsGuidelineCheck extends GuidelineCheck {

    private List<HashAlgorithm> recommendedAlgorithms;

    private HashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public HashAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<HashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public HashAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, List<HashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        if (report.getSupportedSignatureAndHashAlgorithms() == null) {
            return new HashAlgorithmsGuidelineCheckResult(TestResult.UNCERTAIN, Collections.emptySet());
        }
        Set<HashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm alg : report.getSupportedSignatureAndHashAlgorithms()) {
            if (!this.recommendedAlgorithms.contains(alg.getHashAlgorithm())) {
                nonRecommended.add(alg.getHashAlgorithm());
            }
        }
        return new HashAlgorithmsGuidelineCheckResult(TestResult.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String getId() {
        return "HashAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<HashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
