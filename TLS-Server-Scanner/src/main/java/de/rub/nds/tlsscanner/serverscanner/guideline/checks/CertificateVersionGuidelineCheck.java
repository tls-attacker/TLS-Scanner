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
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateVersionGuidelineCheckResult;
import de.rub.nds.x509attacker.constants.X509Version;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateVersionGuidelineCheck extends CertificateGuidelineCheck {

    private X509Version version;

    private CertificateVersionGuidelineCheck() {
        super(null, null);
    }

    public CertificateVersionGuidelineCheck(
            String name, RequirementLevel requirementLevel, X509Version version) {
        super(name, requirementLevel);
        this.version = version;
    }

    public CertificateVersionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            X509Version version) {
        super(name, requirementLevel, onlyOneCertificate);
        this.version = version;
    }

    public CertificateVersionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            X509Version version) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.version = version;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        CertificateReport report = chain.getLeafReport();
        return new CertificateVersionGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(this.version == report.getVersion()),
                report.getVersion());
    }

    @Override
    public String toString() {
        return "CertificateVersion_" + getRequirementLevel() + "_" + version;
    }

    public X509Version getVersion() {
        return version;
    }
}
