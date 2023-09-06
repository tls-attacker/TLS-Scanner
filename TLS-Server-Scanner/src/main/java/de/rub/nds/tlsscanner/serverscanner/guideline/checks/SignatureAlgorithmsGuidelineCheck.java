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
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAlgorithmsGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<SignatureAlgorithm> recommendedAlgorithms;

    private SignatureAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public SignatureAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        List<SignatureAndHashAlgorithm> algorithms =
                report.getSupportedSignatureAndHashAlgorithms();
        if (algorithms != null) {
            Set<SignatureAlgorithm> notRecommended = new HashSet<>();
            for (SignatureAndHashAlgorithm alg : algorithms) {
                if (!this.recommendedAlgorithms.contains(alg.getSignatureAlgorithm())) {
                    notRecommended.add(alg.getSignatureAlgorithm());
                }
            }
            return new SignatureAlgorithmsGuidelineCheckResult(
                    getName(), GuidelineAdherence.of(notRecommended.isEmpty()), notRecommended);
        } else {
            return new SignatureAlgorithmsGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED, null);
        }
    }

    @Override
    public String toString() {
        return "SignatureAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
