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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SignatureAndHashAlgorithmsCertGuidelineCheck extends ConditionalGuidelineCheck {

    private List<SignatureAndHashAlgorithm> algorithms;

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        for (SignatureAndHashAlgorithm algorithm : report.getSupportedSignatureAndHashAlgorithmsCert()) {
            if (!this.algorithms.contains(algorithm)) {
                nonRecommended.add(algorithm);
            }
        }
        if (nonRecommended.isEmpty()) {
            result.update(GuidelineCheckStatus.PASSED, "Only listed signature and hash algorithms are supported.");
            return;
        }
        result.append("The following signature and hash algorithms were supported but not recommended:\n");
        result.append(Joiner.on('\n').join(nonRecommended));
        result.updateStatus(GuidelineCheckStatus.FAILED);
    }

    public List<SignatureAndHashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAndHashAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }

}
