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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class SignatureAndHashAlgorithmsCertGuidelineCheck extends CertificateGuidelineCheck {

    private List<SignatureAndHashAlgorithm> algorithms;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        List<SignatureAndHashAlgorithm> nonRecommended = new ArrayList<>();
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (report.getSignatureAndHashAlgorithm() == null) {
                return Pair.of(GuidelineCheckStatus.UNCERTAIN, "Certificate is missing supported algorithms.");
            }

            if (!this.algorithms.contains(report.getSignatureAndHashAlgorithm())) {
                nonRecommended.add(report.getSignatureAndHashAlgorithm());
            }
        }
        if (nonRecommended.isEmpty()) {
            return Pair.of(GuidelineCheckStatus.PASSED, "Only listed signature and hash algorithms are supported.");
        }
        return Pair.of(GuidelineCheckStatus.FAILED,
            "The following signature and hash algorithms were supported but not recommended:\n"
                + Joiner.on('\n').join(nonRecommended));
    }

    public List<SignatureAndHashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAndHashAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
