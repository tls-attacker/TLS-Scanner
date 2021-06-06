/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model.certificate;

import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.List;

public class ExtendedKeyUsageCertificateCheck extends BasicGuidelineCertificateCheck {

    private List<KeyPurposeId> purposeIds;

    @Override
    public boolean checkChain(CertificateChain chain) {
        if (chain.getCertificateReportList().isEmpty()) {
            return false;
        }
        CertificateReport report = chain.getCertificateReportList().get(0);
        ExtendedKeyUsage extension =
            ExtendedKeyUsage.fromExtensions(report.convertToCertificateHolder().getExtensions());
        if (extension == null) {
            return false;
        }
        for (KeyPurposeId purposeId : purposeIds) {
            if (!extension.hasKeyPurposeId(purposeId)) {
                return false;
            }
        }
        return true;
    }

    public List<KeyPurposeId> getPurposeIds() {
        return purposeIds;
    }

    public void setPurposeIds(List<KeyPurposeId> purposeIds) {
        this.purposeIds = purposeIds;
    }
}
