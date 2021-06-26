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
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.List;

public abstract class CertificateGuidelineCheck extends ConditionalGuidelineCheck {

    private Integer count;

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        int passCount = 0;
        int uncertainCount = 0;
        for (int i = 0; i < report.getCertificateChainList().size(); i++) {
            CertificateChain chain = report.getCertificateChainList().get(i);
            result.append("Certificate Check #").append(i + 1).append('\n');
            GuidelineCheckStatus status = this.evaluateChain(chain, result);
            result.append("Status: ").append(status).append('\n');
            if (GuidelineCheckStatus.PASSED.equals(status)) {
                passCount++;
            } else if (GuidelineCheckStatus.UNCERTAIN.equals(status)) {
                uncertainCount++;
            }
        }
        int required = this.requiredPassCount(report.getCertificateChainList());
        if (passCount >= required) {
            result.setStatus(GuidelineCheckStatus.PASSED);
            return;
        }
        if (passCount + uncertainCount >= required) {
            result.setStatus(GuidelineCheckStatus.UNCERTAIN);
            return;
        }
        result.setStatus(GuidelineCheckStatus.FAILED);
    }

    public abstract GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result);

    public int requiredPassCount(List<CertificateChain> chains) {
        return this.count == null ? chains.size() : this.count;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }
}
