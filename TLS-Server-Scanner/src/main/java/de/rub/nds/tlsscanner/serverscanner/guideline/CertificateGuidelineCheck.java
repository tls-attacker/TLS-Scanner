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
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public abstract class CertificateGuidelineCheck extends ConditionalGuidelineCheck {

    private Integer count;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        StringBuilder sb = new StringBuilder();
        int passCount = 0;
        int uncertainCount = 0;
        for (int i = 0; i < report.getCertificateChainList().size(); i++) {
            CertificateChain chain = report.getCertificateChainList().get(i);
            Pair<GuidelineCheckStatus, String> result = this.evaluateChain(chain);
            sb.append("Certificate Check #").append(i + 1).append(" ").append(result.getLeft()).append('\n');
            sb.append(result.getRight()).append('\n');
            if (GuidelineCheckStatus.PASSED.equals(result.getLeft())) {
                passCount++;
            } else if (GuidelineCheckStatus.UNCERTAIN.equals(result.getLeft())) {
                uncertainCount++;
            }
        }
        int required = this.requiredPassCount(report.getCertificateChainList());
        if (passCount >= required) {
            return Pair.of(GuidelineCheckStatus.PASSED, sb.toString());
        }
        if (passCount + uncertainCount >= required) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, sb.toString());
        }
        return Pair.of(GuidelineCheckStatus.FAILED, sb.toString());
    }

    public abstract Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain);

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
