/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAndHashAlgorithmsCertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAndHashAlgorithmsCertificateGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;

    private SignatureAndHashAlgorithmsCertificateGuidelineCheck() {
        super(null, null);
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public SignatureAndHashAlgorithmsCertificateGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @SuppressWarnings("unchecked")
    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm algorithm : ((ListResult<SignatureAndHashAlgorithm>) report
            .getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_CERT)).getList()) {
            if (!this.recommendedAlgorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        return new SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(TestResults.of(nonRecommended.isEmpty()),
            nonRecommended);
    }

    @Override
    public String getId() {
        return "SignatureAndHashAlgorithmsCert_" + getRequirementLevel() + "_" + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
