/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.Objects;

public class ExtendedKeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private ExtendedKeyUsageCertificateCheck() {
        super(null, null);
    }

    public ExtendedKeyUsageCertificateCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public ExtendedKeyUsageCertificateCheck(String name, RequirementLevel requirementLevel,
        boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public ExtendedKeyUsageCertificateCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        return new GuidelineCheckResult(
            TestResult.of(report.getExtendedKeyUsageServerAuth() && !report.getAnyExtendedKeyUsage())) {
            @Override
            public String display() {
                return Objects.equals(TestResult.TRUE, getResult())
                    ? "Certificate has extended key usage for server auth."
                    : "Certificate is missing extended key usage for server auth.";
            }
        };
    }

    @Override
    public String getId() {
        return "ExtendedKeyUsage_" + getRequirementLevel();
    }

}
