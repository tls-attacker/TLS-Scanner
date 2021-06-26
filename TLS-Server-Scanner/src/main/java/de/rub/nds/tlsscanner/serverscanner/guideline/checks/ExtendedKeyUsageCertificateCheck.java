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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class ExtendedKeyUsageCertificateCheck extends CertificateGuidelineCheck {

    private String purpose;

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        ExtendedKeyUsage extension =
            ExtendedKeyUsage.fromExtensions(report.convertToCertificateHolder().getExtensions());
        if (extension == null) {
            result.append("Certificate is missing Extended Key Usage extension.");
            return GuidelineCheckStatus.FAILED;
        }
        KeyPurposeId id = KeyPurposeId.getInstance(new ASN1ObjectIdentifier(this.purpose));
        if (!extension.hasKeyPurposeId(id)) {
            result.append("Missing purpose id " + id);
            return GuidelineCheckStatus.FAILED;
        }
        result.append("Extended Key Usage has purpose " + id);
        return GuidelineCheckStatus.PASSED;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }
}
