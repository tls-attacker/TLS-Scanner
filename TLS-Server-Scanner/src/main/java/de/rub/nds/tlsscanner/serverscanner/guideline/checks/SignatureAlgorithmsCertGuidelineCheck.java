/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.List;

public class SignatureAlgorithmsCertGuidelineCheck extends CertificateGuidelineCheck {

    private List<SignatureAlgorithm> algorithms;

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (report.getSignatureAndHashAlgorithm() == null) {
            result.append("Certificate is missing supported algorithms.");
            return GuidelineCheckStatus.UNCERTAIN;
        }
        if (!this.algorithms.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            result.append("The following signature algorithm is used but not recommended: ");
            result.append(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm());
            return GuidelineCheckStatus.FAILED;
        }
        result.append("Only listed signature are used.");
        return GuidelineCheckStatus.PASSED;
    }

    public List<SignatureAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
