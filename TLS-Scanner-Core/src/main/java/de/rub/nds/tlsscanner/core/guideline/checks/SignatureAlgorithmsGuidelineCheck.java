/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.checks;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.results.SignatureAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAlgorithmsGuidelineCheck extends TlsGuidelineCheck {

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
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        List<SignatureAndHashAlgorithm> algorithms;
        if (report.getResultMap()
                .containsKey(TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS)) {
            algorithms =
                    report.getListResult(
                                    TlsAnalyzedProperty
                                            .CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                                    SignatureAndHashAlgorithm.class)
                            .getList();
        } else {
            algorithms = report.getSupportedSignatureAndHashAlgorithms();
        }
        if (algorithms != null) {
            Set<SignatureAlgorithm> notRecommended = new HashSet<>();
            for (SignatureAndHashAlgorithm alg : algorithms) {
                if (!this.recommendedAlgorithms.contains(alg.getSignatureAlgorithm())) {
                    notRecommended.add(alg.getSignatureAlgorithm());
                }
            }
            return new SignatureAlgorithmsGuidelineCheckResult(
                    this, GuidelineAdherence.of(notRecommended.isEmpty()), notRecommended);
        } else {
            return new SignatureAlgorithmsGuidelineCheckResult(
                    this, GuidelineAdherence.CHECK_FAILED, null);
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
