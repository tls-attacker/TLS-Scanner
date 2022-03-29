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
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateValidityGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.time.Duration;
import java.time.Instant;

public class CertificateValidityGuidelineCheck extends CertificateGuidelineCheck {

    private int days;

    private CertificateValidityGuidelineCheck() {
        super(null, null);
    }

    public CertificateValidityGuidelineCheck(String name, RequirementLevel requirementLevel, int days) {
        super(name, requirementLevel);
        this.days = days;
    }

    public CertificateValidityGuidelineCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate,
        int days) {
        super(name, requirementLevel, onlyOneCertificate);
        this.days = days;
    }

    public CertificateValidityGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, boolean onlyOneCertificate, int days) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.days = days;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        Duration validityPeriod = Duration.between(Instant.ofEpochMilli(report.getValidFrom().getTime()),
            Instant.ofEpochMilli(report.getValidTo().getTime()));
        return new CertificateValidityGuidelineCheckResult(TestResult.of(validityPeriod.toDays() <= this.days), days,
            validityPeriod.toDays());
    }

    @Override
    public String getId() {
        return "CertificateValidity_" + getRequirementLevel() + "_" + days;
    }

    public int getDays() {
        return days;
    }

}
