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

import java.util.List;

public class HasPublicKeyCertificateCheck extends BasicGuidelineCertificateCheck {

    @Override
    public boolean checkChain(CertificateChain chain) {
        if (chain.getCertificateReportList().isEmpty()) {
            return false;
        }
        CertificateReport report = chain.getCertificateReportList().get(0);
        return report.getPublicKey() != null;// TODO reicht das aus?
    }

    @Override
    public int passCount(List<CertificateChain> chains) {
        return 1;
    }
}
