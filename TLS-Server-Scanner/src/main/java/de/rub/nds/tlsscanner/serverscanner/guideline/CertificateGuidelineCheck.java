/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.ArrayList;
import java.util.List;

public abstract class CertificateGuidelineCheck extends GuidelineCheck {

    /**
     * <code>true</code> if only one certificate has to pass the check. Otherwise all certificates have to pass.
     */
    private boolean onlyOneCertificate;

    public CertificateGuidelineCheck(String name, RequirementLevel requirementLevel) {
        this(name, requirementLevel, false);
    }

    public CertificateGuidelineCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel);
        this.onlyOneCertificate = onlyOneCertificate;
    }

    public CertificateGuidelineCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        boolean onlyOneCertificate) {
        super(name, requirementLevel, condition);
        this.onlyOneCertificate = onlyOneCertificate;
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        boolean passFlag = false;
        boolean failFlag = false;
        boolean uncertainFlag = false;
        CertificateGuidelineCheckResult result = new CertificateGuidelineCheckResult();
        for (int i = 0; i < report.getCertificateChainList().size(); i++) {
            CertificateChain chain = report.getCertificateChainList().get(i);
            GuidelineCheckResult currentResult = this.evaluateChain(chain);
            result.addResult(currentResult);
            if (TestResult.TRUE.equals(currentResult.getResult())) {
                passFlag = true;
            } else if (TestResult.FALSE.equals(currentResult.getResult())) {
                failFlag = true;
            } else {
                uncertainFlag = true;
            }
        }
        if (this.onlyOneCertificate && passFlag) {
            result.setResult(TestResult.TRUE);
        } else if (passFlag && !uncertainFlag && !failFlag) {
            result.setResult(TestResult.TRUE);
        } else if (failFlag) {
            result.setResult(TestResult.FALSE);
        } else {
            result.setResult(TestResult.UNCERTAIN);
        }
        return result;
    }

    public abstract GuidelineCheckResult evaluateChain(CertificateChain chain);

    public boolean isOnlyOneCertificate() {
        return onlyOneCertificate;
    }

    public void setOnlyOneCertificate(boolean onlyOneCertificate) {
        this.onlyOneCertificate = onlyOneCertificate;
    }

    public static class CertificateGuidelineCheckResult extends GuidelineCheckResult {

        private final List<GuidelineCheckResult> results = new ArrayList<>();

        public CertificateGuidelineCheckResult() {
            super(TestResult.UNCERTAIN);
        }

        @Override
        public String display() {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < results.size(); i++) {
                GuidelineCheckResult result = this.results.get(i);
                stringBuilder.append("Certificate Check #").append(i + 1).append('\n');
                stringBuilder.append(result.display()).append('\n');
            }
            return stringBuilder.toString();
        }

        public void addResult(GuidelineCheckResult result) {
            this.results.add(result);
        }

        public List<GuidelineCheckResult> getResults() {
            return results;
        }
    }
}
