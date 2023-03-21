/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Objects;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class CertificateGuidelineCheck extends GuidelineCheck<ServerReport> {

    /**
     * <code>true</code> if only at least one certificate has to pass the check. Otherwise, all
     * certificates have to pass. <br>
     * Used for the NIST requirement: At a minimum, TLS servers conforming to this specification
     * shall be configured with an RSA signature certificate or an ECDSA signature certificate.
     */
    private boolean atLeastOneCertificateShallPass;

    private CertificateGuidelineCheck() {
        super(null, null);
    }

    public CertificateGuidelineCheck(String name, RequirementLevel requirementLevel) {
        this(name, requirementLevel, false);
    }

    public CertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean atLeastOneCertificateShallPass) {
        super(name, requirementLevel);
        this.atLeastOneCertificateShallPass = atLeastOneCertificateShallPass;
    }

    public CertificateGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean atLeastOneCertificateShallPass) {
        super(name, requirementLevel, condition);
        this.atLeastOneCertificateShallPass = atLeastOneCertificateShallPass;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        boolean passFlag = false;
        boolean failFlag = false;
        boolean uncertainFlag = false;
        CertificateGuidelineCheckResult result = new CertificateGuidelineCheckResult();
        for (int i = 0; i < report.getCertificateChainList().size(); i++) {
            CertificateChain chain = report.getCertificateChainList().get(i);
            GuidelineCheckResult currentResult = this.evaluateChain(chain);
            result.addResult(currentResult);
            if (Objects.equals(TestResults.TRUE, currentResult.getResult())) {
                passFlag = true;
            } else if (Objects.equals(TestResults.FALSE, currentResult.getResult())) {
                failFlag = true;
            } else {
                uncertainFlag = true;
            }
        }
        if (this.atLeastOneCertificateShallPass && passFlag) {
            result.setResult(TestResults.TRUE);
        } else if (passFlag && !uncertainFlag && !failFlag) {
            result.setResult(TestResults.TRUE);
        } else if (failFlag) {
            result.setResult(TestResults.FALSE);
        } else {
            result.setResult(TestResults.UNCERTAIN);
        }
        return result;
    }

    public abstract GuidelineCheckResult evaluateChain(CertificateChain chain);

    public boolean isAtLeastOneCertificateShallPass() {
        return atLeastOneCertificateShallPass;
    }

    public void setAtLeastOneCertificateShallPass(boolean atLeastOneCertificateShallPass) {
        this.atLeastOneCertificateShallPass = atLeastOneCertificateShallPass;
    }
}
