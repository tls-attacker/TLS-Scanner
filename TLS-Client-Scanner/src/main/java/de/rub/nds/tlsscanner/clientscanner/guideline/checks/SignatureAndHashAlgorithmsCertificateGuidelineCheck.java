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
import de.rub.nds.tlsscanner.clientscanner.guideline.results.X509SignatureAlgorithmGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAndHashAlgorithmsCertificateGuidelineCheck
        extends GuidelineCheck<ClientReport> {

    private List<X509SignatureAlgorithm> recommendedAlgorithms;

    private SignatureAndHashAlgorithmsCertificateGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<X509SignatureAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, CertificateGuidelineCheck.PRECONDITION);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<X509SignatureAlgorithm> recommendedAlgorithms) {
        super(
                name,
                requirementLevel,
                GuidelineCheckCondition.and(Arrays.asList(CertificateGuidelineCheck.PRECONDITION, condition)));
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        Set<X509SignatureAlgorithm> nonRecommended = new HashSet<>();
        for (X509SignatureAlgorithm algorithm : report.getSupportedCertSignatureAlgorithms()) {
            if (!recommendedAlgorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        return new X509SignatureAlgorithmGuidelineCheckResult(
                getName(), GuidelineAdherence.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String toString() {
        return "SignatureAndHashAlgorithmsCert_"
                + getRequirementLevel()
                + "_"
                + recommendedAlgorithms;
    }

    public List<X509SignatureAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
