/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import com.google.common.base.Joiner;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HashAlgorithmsGuidelineCheck extends ConditionalGuidelineCheck {

    private List<HashAlgorithm> algorithms;

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        if (report.getSupportedSignatureAndHashAlgorithms() == null) {
            result.update(GuidelineCheckStatus.UNCERTAIN, "Site Report is missing supported algorithms.");
            return;
        }
        Set<HashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm alg : report.getSupportedSignatureAndHashAlgorithms()) {
            if (!this.algorithms.contains(alg.getHashAlgorithm())) {
                nonRecommended.add(alg.getHashAlgorithm());
            }
        }
        if (nonRecommended.isEmpty()) {
            result.update(GuidelineCheckStatus.PASSED, "Only listed hash algorithms are supported.");
        } else {
            result.append("The following hash algorithms were supported but not recommended:\n");
            result.append(Joiner.on('\n').join(nonRecommended));
            result.setStatus(GuidelineCheckStatus.FAILED);
        }
    }

    public List<HashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<HashAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
