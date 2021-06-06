/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model.certificate;

import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.List;

public class SignatureCertificateCheck extends BasicGuidelineCertificateCheck {

    private Integer passCount;
    private List<SignatureAlgorithm> algorithms;

    @Override
    public boolean checkChain(CertificateChain chain) {
        if (chain.getCertificateReportList().isEmpty()) {
            return false;
        }
        CertificateReport report = chain.getCertificateReportList().get(0);
        return this.algorithms.contains(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm());
    }

    @Override
    public int passCount(List<CertificateChain> chains) {
        return this.passCount == null ? chains.size() : passCount;
    }

    public Integer getPassCount() {
        return passCount;
    }

    public void setPassCount(Integer passCount) {
        this.passCount = passCount;
    }

    public List<SignatureAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<SignatureAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
