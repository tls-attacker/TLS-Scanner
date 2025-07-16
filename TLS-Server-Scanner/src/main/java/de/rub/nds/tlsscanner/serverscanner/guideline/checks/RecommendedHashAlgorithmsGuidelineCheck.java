/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.RecommendedHashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RecommendedHashAlgorithmsGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<HashAlgorithm> recommendedAlgorithms;

    private RecommendedHashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public RecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<HashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public RecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<HashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        List<SignatureAndHashAlgorithm> supportedAlgorithms =
                report.getSupportedSignatureAndHashAlgorithms();
        if (supportedAlgorithms != null) {
            Set<HashAlgorithm> notRecommendedButSupportedAlgorithms = new HashSet<>();
            for (SignatureAndHashAlgorithm alg : supportedAlgorithms) {
                if (!this.recommendedAlgorithms.contains(alg.getHashAlgorithm())) {
                    notRecommendedButSupportedAlgorithms.add(alg.getHashAlgorithm());
                }
            }
            return new RecommendedHashAlgorithmsGuidelineCheckResult(
                    getName(),
                    GuidelineAdherence.of(notRecommendedButSupportedAlgorithms.isEmpty()),
                    notRecommendedButSupportedAlgorithms);
        } else {
            return new RecommendedHashAlgorithmsGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED, Collections.emptySet());
        }
    }

    @Override
    public String toString() {
        return "RecommendedHashAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<HashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
