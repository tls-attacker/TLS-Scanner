/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CertificateSignatureAndHashAlgorithmAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        Set<ObjectIdentifier> algorithms = new HashSet<>();
        List<CertificateChainReport> chainList = report.getCertificateChainList();
        if (chainList == null) {
            return;
        }
        for (CertificateChainReport chain : chainList) {
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
                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHM_OIDS,
                new ArrayList<>(algorithms));
        List<X509SignatureAlgorithm> x509SignatureAlgorithms = new LinkedList<>();
        for (ObjectIdentifier oid : algorithms) {
            x509SignatureAlgorithms.add(
                    X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded()));
        }
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS,
                new ArrayList<>(x509SignatureAlgorithms));
    }
}
