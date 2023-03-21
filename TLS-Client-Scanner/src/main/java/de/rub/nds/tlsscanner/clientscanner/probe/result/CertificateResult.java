/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import java.util.LinkedList;
import java.util.Set;

public class CertificateResult extends ProbeResult<ClientReport> {

    private final Set<CertificateChain> clientCertificates;

    public CertificateResult(Set<CertificateChain> clientCertificates) {
        super(TlsProbeType.CERTIFICATE);
        this.clientCertificates = clientCertificates;
    }

    @Override
    protected void mergeData(ClientReport report) {
        if (clientCertificates != null) {
            report.setCertificateChainList(new LinkedList<>(clientCertificates));
        }
    }
}
