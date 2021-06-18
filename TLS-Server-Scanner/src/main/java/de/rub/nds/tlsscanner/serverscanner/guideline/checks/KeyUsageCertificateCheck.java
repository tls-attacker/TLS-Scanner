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
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.Arrays;
import java.util.List;

public class KeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private final static List<SignatureAlgorithm> DIGITAL_SIGNATURE =
        Arrays.asList(SignatureAlgorithm.RSA, SignatureAlgorithm.ECDSA, SignatureAlgorithm.DSA);

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        KeyUsage extension = KeyUsage.fromExtensions(report.convertToCertificateHolder().getExtensions());
        if (extension == null) {
            return Pair.of(GuidelineCheckStatus.FAILED, "Certificate is missing Key Usage extension.");
        }
        if (DIGITAL_SIGNATURE.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            if (!extension.hasUsages(KeyUsage.digitalSignature)) {
                return Pair.of(GuidelineCheckStatus.FAILED, "Missing digitalSignature Key Usage.");
            }
        }
        if (report.getPublicKey() instanceof CustomDhPublicKey) {
            // TODO only for ECDH certificate, DH certificate
            if (!extension.hasUsages(KeyUsage.keyAgreement)) {
                return Pair.of(GuidelineCheckStatus.FAILED, "Missing keyAgreement Key Usage.");
            }
        }
        return Pair.of(GuidelineCheckStatus.PASSED, "Key Usage has correct purposes.");
    }
}
