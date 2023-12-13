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
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Objects;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtendedKeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private ExtendedKeyUsageCertificateCheck() {
        super(null, null);
    }

    public ExtendedKeyUsageCertificateCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public ExtendedKeyUsageCertificateCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public ExtendedKeyUsageCertificateCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        return new GuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(
                        Boolean.TRUE.equals(report.getExtendedKeyUsageServerAuth())
                                && Boolean.FALSE.equals(report.getExtendedKeyUsagePresent()))) {
            @Override
            public String toString() {
                return Objects.equals(GuidelineAdherence.ADHERED, getAdherence())
                        ? "Certificate has extended key usage for server auth."
                        : "Certificate is missing extended key usage for server auth.";
            }
        };
    }

    @Override
    public String toString() {
        return "ExtendedKeyUsage_" + getRequirementLevel();
    }
}
