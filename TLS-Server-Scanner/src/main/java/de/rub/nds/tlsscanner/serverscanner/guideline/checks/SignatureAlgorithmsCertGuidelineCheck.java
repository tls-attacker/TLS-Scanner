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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public class SignatureAlgorithmsCertGuidelineCheck extends CertificateGuidelineCheck {

    private List<SignatureAlgorithm> algorithms;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (report.getSignatureAndHashAlgorithm() == null) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, "Certificate is missing supported algorithms.");
        }
        if (!this.algorithms.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            return Pair.of(GuidelineCheckStatus.FAILED,
                "The following signature algorithm is used but not recommended: "
                    + report.getSignatureAndHashAlgorithm().getSignatureAlgorithm());
        }
        return Pair.of(GuidelineCheckStatus.PASSED, "Only listed signature are used.");
    }

    public List<SignatureAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
