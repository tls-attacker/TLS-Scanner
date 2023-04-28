/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CertificateSignatureAndHashAlgorithmAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        Set<SignatureAndHashAlgorithm> algorithms = new HashSet<>();
        List<CertificateChain> certList = report.getCertificateChainList();
        if (certList == null) {
            return;
        }
        for (CertificateChain chain : report.getCertificateChainList()) {
            if (chain.getCertificateReportList() == null
                    || chain.getCertificateReportList().isEmpty()) {
                continue;
            }
            SignatureAndHashAlgorithm algorithm =
                    chain.getCertificateReportList().get(0).getSignatureAndHashAlgorithm();
            if (algorithm != null) {
                algorithms.add(algorithm);
            }
        }
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT,
                new ListResult<>(
                        new ArrayList<>(algorithms),
                        TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT.name()));
    }
}
