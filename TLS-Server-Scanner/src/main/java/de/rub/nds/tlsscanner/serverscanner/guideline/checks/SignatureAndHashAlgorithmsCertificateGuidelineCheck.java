/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAndHashAlgorithmsCertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAndHashAlgorithmsCertificateGuidelineCheck
        extends GuidelineCheck<ServerReport> {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;

    private SignatureAndHashAlgorithmsCertificateGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm algorithm :
                report.getSupportedSignatureAndHashAlgorithmsCert()) {
            if (!recommendedAlgorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        return new SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(
                TestResults.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAndHashAlgorithmsCert_"
                + getRequirementLevel()
                + "_"
                + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
