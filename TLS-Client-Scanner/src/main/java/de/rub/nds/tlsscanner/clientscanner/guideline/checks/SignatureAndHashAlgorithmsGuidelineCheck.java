/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.SignatureAndHashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAndHashAlgorithmsGuidelineCheck extends GuidelineCheck<ClientReport> {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;
    private boolean tls13;

    private SignatureAndHashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms,
            boolean tls13) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
        this.tls13 = tls13;
    }

    public SignatureAndHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms,
            boolean tls13) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
        this.tls13 = tls13;
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        List<SignatureAndHashAlgorithm> algorithms =
                report.getClientAdvertisedSignatureAndHashAlgorithms();
        if (algorithms == null || algorithms.isEmpty()) {
            return new SignatureAndHashAlgorithmsGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED, null);
        }
        Set<SignatureAndHashAlgorithm> notRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm alg : algorithms) {
            if (!this.recommendedAlgorithms.contains(alg)) {
                notRecommended.add(alg);
            }
        }
        return new SignatureAndHashAlgorithmsGuidelineCheckResult( // TODO this needs to
                // be a new result now
                getName(), GuidelineAdherence.of(notRecommended.isEmpty()), notRecommended);
    }

    @Override
    public String toString() {
        return "SignatureAndHashAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }

    public boolean isTls13() {
        return tls13;
    }
}
