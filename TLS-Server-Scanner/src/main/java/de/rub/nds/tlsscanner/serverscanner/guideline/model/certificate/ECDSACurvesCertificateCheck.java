/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model.certificate;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.List;

public class ECDSACurvesCertificateCheck extends BasicGuidelineCertificateCheck {

    private List<NamedGroup> curves;

    @Override
    public boolean checkChain(CertificateChain chain) {
        if (chain.getCertificateReportList().isEmpty()) {
            return true;
        }
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            return true;
        }
        // TODO named groups wirklich überprüfen
        return false;
    }

    public List<NamedGroup> getCurves() {
        return curves;
    }

    public void setCurves(List<NamedGroup> curves) {
        this.curves = curves;
    }
}
