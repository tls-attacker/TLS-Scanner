/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateCurveGuidelineCheckResult;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<X509NamedCurve> recommendedNamedParameters;

    private CertificateCurveGuidelineCheck() {
        super(null, null);
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<X509NamedCurve> recommendedNamedParameters) {
        super(name, requirementLevel);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            List<X509NamedCurve> recommendedNamedParameters) {
        super(name, requirementLevel, onlyOneCertificate);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    public CertificateCurveGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            List<X509NamedCurve> recommendedNamedParameters) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.recommendedNamedParameters = recommendedNamedParameters;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chainReport) {
        if (!SignatureAlgorithm.ECDSA.equals(chainReport.getLeafReport().getSignatureAlgorithm())) {
            return new CertificateCurveGuidelineCheckResult(getName(), GuidelineAdherence.ADHERED);
        }
        if (!(chainReport.getLeafReport().getPublicKey() instanceof EcdsaPublicKey)
                && !(chainReport.getLeafReport().getPublicKey() instanceof EcdhPublicKey)) {
            return new CertificateCurveGuidelineCheckResult(
                    getName(), GuidelineAdherence.CHECK_FAILED);
        }
        // TODO unsafe check for ecdh

        X509NamedCurve namedCurve = chainReport.getLeafReport().getNamedCurve();
        if (!this.recommendedNamedParameters.contains(namedCurve)) {
            return new CertificateCurveGuidelineCheckResult(
                    getName(), GuidelineAdherence.VIOLATED, false, namedCurve);
        }
        return new CertificateCurveGuidelineCheckResult(
                getName(), GuidelineAdherence.ADHERED, true, namedCurve);
    }

    @Override
    public String toString() {
        return "CertificateCurve_" + getRequirementLevel() + "_" + recommendedNamedParameters;
    }

    public List<X509NamedCurve> getRecommendedNamedParameters() {
        return recommendedNamedParameters;
    }
}
