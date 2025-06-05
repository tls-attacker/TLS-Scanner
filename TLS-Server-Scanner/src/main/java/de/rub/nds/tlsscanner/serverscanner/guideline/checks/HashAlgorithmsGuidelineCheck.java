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
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.HashAlgorithmsGuidelineCheckResult;
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
public class HashAlgorithmsGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<HashAlgorithm> algorithmsInQuestion;
    // If false this class checks if the provided cipher suites are NOT supported.
    private boolean recommended;

    private HashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public HashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<HashAlgorithm> algorithmsInQuestion) {
        super(name, requirementLevel);
        this.algorithmsInQuestion = algorithmsInQuestion;
        this.recommended = true;
        // Default case, this means the algorithmsInQuestion are expected to be supported.
    }

    public HashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<HashAlgorithm> algorithmsInQuestion) {
        super(name, requirementLevel, condition);
        this.algorithmsInQuestion = algorithmsInQuestion;
        this.recommended = true;
        // Default case, this means the algorithmsInQuestion are expected to be supported.
    }

    public HashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<HashAlgorithm> algorithmsInQuestion,
            boolean recommended) {
        super(name, requirementLevel);
        this.algorithmsInQuestion = algorithmsInQuestion;
        this.recommended = recommended;
    }

    public HashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<HashAlgorithm> algorithmsInQuestion,
            boolean recommended) {
        super(name, requirementLevel, condition);
        this.algorithmsInQuestion = algorithmsInQuestion;
        this.recommended = recommended;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        List<SignatureAndHashAlgorithm> supportedAlgorithms =
                report.getSupportedSignatureAndHashAlgorithms();
        if (supportedAlgorithms != null) {
            Set<HashAlgorithm> nonRecommendedAlgorithms = new HashSet<>();
            if (!recommended) {
                for (SignatureAndHashAlgorithm alg : supportedAlgorithms) {
                    if (this.algorithmsInQuestion.contains(alg.getHashAlgorithm())) {
                        nonRecommendedAlgorithms.add(alg.getHashAlgorithm());
                    }
                }
            } else {
                for (SignatureAndHashAlgorithm alg : supportedAlgorithms) {
                    if (!this.algorithmsInQuestion.contains(alg.getHashAlgorithm())) {
                        nonRecommendedAlgorithms.add(alg.getHashAlgorithm());
                    }
                }
            }
            return new HashAlgorithmsGuidelineCheckResult(
                    getName(),
                    GuidelineAdherence.of(nonRecommendedAlgorithms.isEmpty()),
                    nonRecommendedAlgorithms,
                    recommended);
        } else {
            return new HashAlgorithmsGuidelineCheckResult(
                    getName(),
                    GuidelineAdherence.CHECK_FAILED,
                    Collections.emptySet(),
                    recommended);
        }
    }

    @Override
    public String toString() {
        return "HashAlgorithms_"
                + getRequirementLevel()
                + "_"
                + algorithmsInQuestion
                + "_"
                + recommended;
    }

    public List<HashAlgorithm> getAlgorithmsInQuestion() {
        return algorithmsInQuestion;
    }

    public boolean isRecommended() {
        return recommended;
    }
}
