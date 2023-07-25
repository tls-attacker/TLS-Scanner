/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import java.util.List;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateCurveGuidelineCheckResult;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<NamedEllipticCurveParameters> recommendedNamedParameters;

    private CertificateCurveGuidelineCheck() {
        super(null, null);
    }

    public CertificateCurveGuidelineCheck(
            String name, RequirementLevel requirementLevel,
            List<NamedEllipticCurveParameters> recommendedNamedParameters) {
        super(name, requirementLevel);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            List<NamedEllipticCurveParameters> recommendedNamedParameters) {
        super(name, requirementLevel, onlyOneCertificate);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            List<NamedEllipticCurveParameters> recommendedNamedParameters) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(
                report.getSignatureAlgorithm())) {
            return new CertificateCurveGuidelineCheckResult(TestResults.TRUE);
        }
        if (!(report.getPublicKey() instanceof EcdsaPublicKey) && !(report.getPublicKey() instanceof EcdhPublicKey)) {
            return new CertificateCurveGuidelineCheckResult(TestResults.UNCERTAIN);
        }
        // TODO unsafe check for ecdh
        NamedEllipticCurveParameters group = ((EcdsaPublicKey) report.getPublicKey()).getParameters();
        if (!this.recommendedNamedParameters.contains(group)) {
            return new CertificateCurveGuidelineCheckResult(TestResults.FALSE, false, group);
        }
        return new CertificateCurveGuidelineCheckResult(TestResults.TRUE, true, group);
    }

    @Override
    public String getId() {
        return "CertificateCurve_" + getRequirementLevel() + "_" + recommendedNamedParameters;
    }

    public List<NamedEllipticCurveParameters> getRecommendedNamedParameters() {
        return recommendedNamedParameters;
    }
}
