/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.checks;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.results.NotRecommendedHashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NotRecommendedHashAlgorithmsGuidelineCheck extends TlsGuidelineCheck {

    private List<HashAlgorithm> notRecommendedAlgorithms;

    private NotRecommendedHashAlgorithmsGuidelineCheck() {
        super(null, null);
    }

    public NotRecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<HashAlgorithm> notRecommendedAlgorithms) {
        super(name, requirementLevel);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    public NotRecommendedHashAlgorithmsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<HashAlgorithm> notRecommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        List<SignatureAndHashAlgorithm> supportedAlgorithms;
        if (report.getResultMap()
                .containsKey(TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS)) {
            supportedAlgorithms =
                    report.getListResult(
                                    TlsAnalyzedProperty
                                            .CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                                    SignatureAndHashAlgorithm.class)
                            .getList();
        } else {
            supportedAlgorithms = report.getSupportedSignatureAndHashAlgorithms();
        }
        if (supportedAlgorithms != null) {
            Set<HashAlgorithm> nonRecommendedAndSupportedAlgorithms = new HashSet<>();
            for (SignatureAndHashAlgorithm alg : supportedAlgorithms) {
                if (this.notRecommendedAlgorithms.contains(alg.getHashAlgorithm())) {
                    nonRecommendedAndSupportedAlgorithms.add(alg.getHashAlgorithm());
                }
            }
            return new NotRecommendedHashAlgorithmsGuidelineCheckResult(
                    this,
                    GuidelineAdherence.of(nonRecommendedAndSupportedAlgorithms.isEmpty()),
                    nonRecommendedAndSupportedAlgorithms);
        } else {
            return new NotRecommendedHashAlgorithmsGuidelineCheckResult(
                    this, GuidelineAdherence.CHECK_FAILED, Collections.emptySet());
        }
    }

    @Override
    public String toString() {
        return "NotRecommendedHashAlgorithms_"
                + getRequirementLevel()
                + "_"
                + notRecommendedAlgorithms;
    }

    public List<HashAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
