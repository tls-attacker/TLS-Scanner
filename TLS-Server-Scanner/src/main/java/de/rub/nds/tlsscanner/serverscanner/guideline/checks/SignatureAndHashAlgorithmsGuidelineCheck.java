/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAndHashAlgorithmsCertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAndHashAlgorithmsGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;
    private boolean tls13;

    private SignatureAndHashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<SignatureAndHashAlgorithm> recommendedAlgorithms, boolean tls13) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
        this.tls13 = tls13;
    }

    public SignatureAndHashAlgorithmsGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, List<SignatureAndHashAlgorithm> recommendedAlgorithms, boolean tls13) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
        this.tls13 = tls13;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        List<SignatureAndHashAlgorithm> algorithms = tls13 ? report.getSupportedSignatureAndHashAlgorithmsTls13()
            : report.getSupportedSignatureAndHashAlgorithms();
        if (algorithms == null) {
            return new SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(TestResults.UNCERTAIN, null);
        }
        Set<SignatureAndHashAlgorithm> notRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm alg : algorithms) {
            if (!this.recommendedAlgorithms.contains(alg)) {
                notRecommended.add(alg);
            }
        }
        return new SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(TestResults.of(notRecommended.isEmpty()),
            notRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAndHashAlgorithms_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }

    public boolean isTls13() {
        return tls13;
    }
}
