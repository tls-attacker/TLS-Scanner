/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateCurveGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<NamedGroup> recommendedGroups;

    private CertificateCurveGuidelineCheck() {
        super(null, null);
    }

    public CertificateCurveGuidelineCheck(String name, RequirementLevel requirementLevel,
        List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel);
        this.recommendedGroups = recommendedGroups;
    }

    public CertificateCurveGuidelineCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate,
        List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel, onlyOneCertificate);
        this.recommendedGroups = recommendedGroups;
    }

    public CertificateCurveGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, boolean onlyOneCertificate, List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.recommendedGroups = recommendedGroups;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            return new CertificateCurveGuidelineCheckResult(TestResult.TRUE);
        }
        if (!(report.getPublicKey() instanceof CustomEcPublicKey)) {
            return new CertificateCurveGuidelineCheckResult(TestResult.UNCERTAIN);
        }
        NamedGroup group = ((CustomEcPublicKey) report.getPublicKey()).getGroup();
        if (!this.recommendedGroups.contains(group)) {
            return new CertificateCurveGuidelineCheckResult(TestResult.FALSE, false, group);
        }
        return new CertificateCurveGuidelineCheckResult(TestResult.TRUE, true, group);
    }

    @Override
    public String getId() {
        return "CertificateCurve_" + getRequirementLevel() + "_" + recommendedGroups;
    }

    public List<NamedGroup> getRecommendedGroups() {
        return recommendedGroups;
    }

}
