/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class CertificateSignatureAndHashAlgorithmAfterProbe extends AfterProbe {
    @Override
    public void analyze(SiteReport report) {
        Set<SignatureAndHashAlgorithm> algorithms = new HashSet<>();
        if (report.getCertificateChainList() == null) {
            return;
        }
        for (CertificateChain chain : report.getCertificateChainList()) {
            if (chain.getCertificateReportList() == null || chain.getCertificateReportList().isEmpty()) {
                continue;
            }
            SignatureAndHashAlgorithm algorithm =
                chain.getCertificateReportList().get(0).getSignatureAndHashAlgorithm();
            if (algorithm != null) {
                algorithms.add(algorithm);
            }
        }
        report.setSupportedSignatureAndHashAlgorithmsCert(new ArrayList<>(algorithms));
    }
}
