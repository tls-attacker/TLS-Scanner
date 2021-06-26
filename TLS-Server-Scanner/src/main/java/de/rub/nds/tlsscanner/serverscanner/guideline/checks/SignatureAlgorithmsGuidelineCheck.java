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
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.ArrayList;
import java.util.List;

public class SignatureAlgorithmsGuidelineCheck extends ConditionalGuidelineCheck {

    private List<SignatureAlgorithm> algorithms;

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        if (report.getSupportedSignatureAndHashAlgorithms() == null) {
            result.update(GuidelineCheckStatus.UNCERTAIN, "Site Report is missing supported algorithms.");
            return;
        }
        List<SignatureAlgorithm> nonRecommended = new ArrayList<>();
        for (SignatureAndHashAlgorithm alg : report.getSupportedSignatureAndHashAlgorithms()) {
            if (!this.algorithms.contains(alg.getSignatureAlgorithm())) {
                nonRecommended.add(alg.getSignatureAlgorithm());
            }
        }
        if (nonRecommended.isEmpty()) {
            result.update(GuidelineCheckStatus.PASSED, "Only listed signature algorithms are supported.");
        } else {
            result.append("The following signature algorithms were supported but not recommended:\n");
            result.append(Joiner.on('\n').join(nonRecommended));
            result.updateStatus(GuidelineCheckStatus.FAILED);
        }
    }

    public List<SignatureAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
