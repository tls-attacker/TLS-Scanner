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
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.ClientSigAndHashCertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.guideline.checks.TlsGuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.results.SignatureAndHashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientSigAndHashCertificateGuidelineCheck extends TlsGuidelineCheck {

    private List<SignatureAndHashAlgorithm> recommendedAlgorithms;

    private ClientSigAndHashCertificateGuidelineCheck() {
        super(null, null);
    }

    public ClientSigAndHashCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    public ClientSigAndHashCertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<SignatureAndHashAlgorithm> recommendedAlgorithms) {
        super(name, requirementLevel, condition);
        this.recommendedAlgorithms = recommendedAlgorithms;
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport tlsReport) {
        ClientReport clientReport;
        if (tlsReport instanceof ClientReport) {
            clientReport = (ClientReport) tlsReport;
        } else {
            return null;
        }
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        List<SignatureAndHashAlgorithm> algorithms =
                clientReport.getClientAdvertisedCertSignatureAndHashAlgorithms() == null
                        ? clientReport.getClientAdvertisedSignatureAndHashAlgorithms()
                        : clientReport.getClientAdvertisedCertSignatureAndHashAlgorithms();
        if (algorithms == null || algorithms.isEmpty()) {
            return new SignatureAndHashAlgorithmsGuidelineCheckResult(
                    this, GuidelineAdherence.CHECK_FAILED, null);
        }
        for (SignatureAndHashAlgorithm algorithm : algorithms) {
            if (!recommendedAlgorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        return new ClientSigAndHashCertificateGuidelineCheckResult(
                this, GuidelineAdherence.of(nonRecommended.isEmpty()), nonRecommended);
    }

    @Override
    public String toString() {
        return "SignatureAndHashAlgorithmsCert_"
                + getRequirementLevel()
                + "_"
                + recommendedAlgorithms;
    }

    public List<SignatureAndHashAlgorithm> getRecommendedAlgorithms() {
        return recommendedAlgorithms;
    }
}
