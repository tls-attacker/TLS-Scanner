/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateCurveGuidelineCheckResult;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<NamedGroup> recommendedGroups;

    private CertificateCurveGuidelineCheck() {
        super(null, null);
    }

    public CertificateCurveGuidelineCheck(
            String name, RequirementLevel requirementLevel, List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel);
        this.recommendedGroups = recommendedGroups;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel, onlyOneCertificate);
        this.recommendedGroups = recommendedGroups;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.recommendedGroups = recommendedGroups;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(
                report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            return new CertificateCurveGuidelineCheckResult(getName(), GuidelineAdherence.ADHERED);
        }
        if (!(report.getPublicKey() instanceof CustomEcPublicKey)) {
            return new CertificateCurveGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED);
        }
        NamedGroup group = ((CustomEcPublicKey) report.getPublicKey()).getGroup();
        if (!this.recommendedGroups.contains(group)) {
            return new CertificateCurveGuidelineCheckResult(
                    getName(), GuidelineAdherence.VIOLATED, false, group);
        }
        return new CertificateCurveGuidelineCheckResult(
                getName(), GuidelineAdherence.ADHERED, true, group);
    }

    @Override
    public String toString() {
        return "CertificateCurve_" + getRequirementLevel() + "_" + recommendedGroups;
    }

    public List<NamedGroup> getRecommendedGroups() {
        return recommendedGroups;
    }
}
