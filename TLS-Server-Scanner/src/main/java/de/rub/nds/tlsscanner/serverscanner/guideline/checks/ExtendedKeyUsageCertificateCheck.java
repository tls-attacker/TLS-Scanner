/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class ExtendedKeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private String purpose;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        ExtendedKeyUsage extension =
            ExtendedKeyUsage.fromExtensions(report.convertToCertificateHolder().getExtensions());
        if (extension == null) {
            return Pair.of(GuidelineCheckStatus.FAILED, "Certificate is missing Extended Key Usage extension.");
        }
        KeyPurposeId id = KeyPurposeId.getInstance(new ASN1ObjectIdentifier(this.purpose));
        if (!extension.hasKeyPurposeId(id)) {
            return Pair.of(GuidelineCheckStatus.FAILED, "Missing purpose id " + id);
        }
        return Pair.of(GuidelineCheckStatus.PASSED, "Extended Key Usage has purpose " + id);
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }
}
