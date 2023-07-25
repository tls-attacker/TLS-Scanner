/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class CertificateSignatureAndHashAlgorithmAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        Set<ObjectIdentifier> algorithms = new HashSet<>();
        List<CertificateChainReport> certList = report.getCertificateChainList();
        if (certList == null) {
            return;
        }
        for (CertificateChainReport chain : report.getCertificateChainList()) {
            if (chain.getCertificateReportList() == null
                    || chain.getCertificateReportList().isEmpty()) {
                continue;
            }
            for (CertificateReport certReport : chain.getCertificateReportList()) {
                ObjectIdentifier algorithm = certReport.getSignatureAndHashAlgorithmOid();
                if (algorithm != null) {
                    algorithms.add(algorithm);
                }
            }
        }
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS,
                new ListResult<>(
                        new ArrayList<>(algorithms),
                        TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS.name()));
    }
}
