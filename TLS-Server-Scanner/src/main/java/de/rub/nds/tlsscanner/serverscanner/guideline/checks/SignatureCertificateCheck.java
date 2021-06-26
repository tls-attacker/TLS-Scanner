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

import java.util.Locale;

public class SignatureCertificateCheck extends CertificateGuidelineCheck {

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        SignatureAlgorithm signatureAlgorithm = report.getSignatureAndHashAlgorithm().getSignatureAlgorithm();
        String keyAlgorithm = report.getPublicKey().getAlgorithm().toUpperCase(Locale.ENGLISH);
        result.append(keyAlgorithm + " key is signed with " + signatureAlgorithm);
        switch (keyAlgorithm) {
            case "EC":
                if (signatureAlgorithm.equals(SignatureAlgorithm.ECDSA)) {
                    return GuidelineCheckStatus.PASSED;
                } else {
                    return GuidelineCheckStatus.FAILED;
                }
            case "DH":
                if (signatureAlgorithm.equals(SignatureAlgorithm.DSA)) {
                    return GuidelineCheckStatus.PASSED;
                } else {
                    return GuidelineCheckStatus.FAILED;
                }
            case "RSA":
            case "DSA":
                if (signatureAlgorithm.equals(SignatureAlgorithm.valueOf(keyAlgorithm))) {
                    return GuidelineCheckStatus.PASSED;
                } else {
                    return GuidelineCheckStatus.FAILED;
                }
        }
        return GuidelineCheckStatus.UNCERTAIN;
    }
}
