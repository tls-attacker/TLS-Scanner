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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SignatureAndHashAlgorithmsCertGuidelineCheck extends CertificateGuidelineCheck {

    private List<SignatureAndHashAlgorithm> algorithms;

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        Set<SignatureAndHashAlgorithm> nonRecommended = new HashSet<>();
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (report.getSignatureAndHashAlgorithm() == null) {
                result.append("Certificate is missing supported algorithms.");
                return GuidelineCheckStatus.UNCERTAIN;
            }

            if (!this.algorithms.contains(report.getSignatureAndHashAlgorithm())) {
                nonRecommended.add(report.getSignatureAndHashAlgorithm());
            }
        }
        if (nonRecommended.isEmpty()) {
            result.append("Only listed signature and hash algorithms are supported.");
            return GuidelineCheckStatus.PASSED;
        }
        result.append("The following signature and hash algorithms were supported but not recommended:\n");
        result.append(Joiner.on('\n').join(nonRecommended));
        return GuidelineCheckStatus.FAILED;
    }

    public List<SignatureAndHashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAndHashAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
