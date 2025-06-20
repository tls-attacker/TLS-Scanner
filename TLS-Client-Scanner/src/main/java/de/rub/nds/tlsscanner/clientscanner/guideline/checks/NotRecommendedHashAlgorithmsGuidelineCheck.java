/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.NotRecommendedHashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NotRecommendedHashAlgorithmsGuidelineCheck extends GuidelineCheck<ClientReport> {

    private List<HashAlgorithm> algorithmsInQuestion;

    private NotRecommendedHashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public NotRecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<HashAlgorithm> algorithmsInQuestion) {
        super(name, requirementLevel);
        this.algorithmsInQuestion = algorithmsInQuestion;
    }

    public NotRecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<HashAlgorithm> algorithmsInQuestion) {
        super(name, requirementLevel, condition);
        this.algorithmsInQuestion = algorithmsInQuestion;
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        List<SignatureAndHashAlgorithm> supportedAlgorithms =
                report.getClientAdvertisedSignatureAndHashAlgorithms();
        if (supportedAlgorithms != null) {
            Set<HashAlgorithm> nonRecommendedAlgorithms = new HashSet<>();
            for (SignatureAndHashAlgorithm alg : supportedAlgorithms) {
                if (this.algorithmsInQuestion.contains(alg.getHashAlgorithm())) {
                    nonRecommendedAlgorithms.add(alg.getHashAlgorithm());
                }
            }
            return new NotRecommendedHashAlgorithmsGuidelineCheckResult(
                    getName(),
                    GuidelineAdherence.of(nonRecommendedAlgorithms.isEmpty()),
                    nonRecommendedAlgorithms);
        } else {
            return new NotRecommendedHashAlgorithmsGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED, Collections.emptySet());
        }
    }

    @Override
    public String toString() {
        return "HashAlgorithms_" + getRequirementLevel() + "_" + algorithmsInQuestion;
    }

    public List<HashAlgorithm> getAlgorithmsInQuestion() {
        return algorithmsInQuestion;
    }
}
