/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SignatureAlgorithmsGuidelineCheck extends GuidelineCheck {

    private List<SignatureAlgorithm> recommendedAlgorithms;

    private SignatureAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public SignatureAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        if (report.getSupportedSignatureAndHashAlgorithms() == null) {
            return new SignatureAlgorithmsGuidelineCheckResult(TestResults.UNCERTAIN, null);
        }
        Set<SignatureAlgorithm> notRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm alg : report.getSupportedSignatureAndHashAlgorithms()) {
            if (!this.recommendedAlgorithms.contains(alg.getSignatureAlgorithm())) {
                notRecommended.add(alg.getSignatureAlgorithm());
            }
        }
        return new SignatureAlgorithmsGuidelineCheckResult(TestResults.of(notRecommended.isEmpty()), notRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
