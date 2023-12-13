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
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateValidityGuidelineCheckResult;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.joda.time.Duration;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateValidityGuidelineCheck extends CertificateGuidelineCheck {

    private int days;

    private CertificateValidityGuidelineCheck() {
        super(null, null);
    }

    public CertificateValidityGuidelineCheck(
            String name, RequirementLevel requirementLevel, int days) {
        super(name, requirementLevel);
        this.days = days;
    }

    public CertificateValidityGuidelineCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate, int days) {
        super(name, requirementLevel, onlyOneCertificate);
        this.days = days;
    }

    public CertificateValidityGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            int days) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.days = days;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        Duration validityPeriod = chain.getLeafReport().getOriginalFullDuration();
        return new CertificateValidityGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(validityPeriod.toStandardDays().getDays() <= this.days),
                days,
                validityPeriod.toStandardDays().getDays());
    }

    @Override
    public String toString() {
        return "CertificateValidity_" + getRequirementLevel() + "_" + days;
    }

    public int getDays() {
        return days;
    }
}
