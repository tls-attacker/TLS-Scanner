/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CertificateResult extends ProbeResult<ServerReport> {

    private final Set<CertificateChain> certificates;
    private final List<NamedGroup> ecdsaPkGroupsStatic;
    private final List<NamedGroup> ecdsaPkGroupsEphemeral;
    private final List<NamedGroup> ecdsaPkGroupsTls13;
    private final List<NamedGroup> ecdsaSigGroupsStatic;
    private final List<NamedGroup> ecdsaSigGroupsEphemeral;
    private final List<NamedGroup> ecdsaCertSigGroupsTls13;

    public CertificateResult(
            Set<CertificateChain> certificates,
            List<NamedGroup> ecdsaPkGroupsStatic,
            List<NamedGroup> ecdsaPkGroupsEphemeral,
            List<NamedGroup> ecdsaSigGroupsStatic,
            List<NamedGroup> ecdsaSigGroupsEphemeral,
            List<NamedGroup> ecdsaPkGroupsTls13,
            List<NamedGroup> ecdsaCertSigGroupsTls13) {
        super(TlsProbeType.CERTIFICATE);
        this.certificates = certificates;
        this.ecdsaPkGroupsStatic = ecdsaPkGroupsStatic;
        this.ecdsaPkGroupsEphemeral = ecdsaPkGroupsEphemeral;
        this.ecdsaSigGroupsStatic = ecdsaSigGroupsStatic;
        this.ecdsaSigGroupsEphemeral = ecdsaSigGroupsEphemeral;
        this.ecdsaPkGroupsTls13 = ecdsaPkGroupsTls13;
        this.ecdsaCertSigGroupsTls13 = ecdsaCertSigGroupsTls13;
    }

    @Override
    public void mergeData(ServerReport report) {
        if (certificates != null) {
            report.setCertificateChainList(new LinkedList<>(certificates));
        }
        report.setEcdsaPkGroupsStatic(ecdsaPkGroupsStatic);
        report.setEcdsaPkGroupsEphemeral(ecdsaPkGroupsEphemeral);
        report.setEcdsaPkGroupsTls13(ecdsaPkGroupsTls13);
        report.setEcdsaSigGroupsStatic(ecdsaSigGroupsStatic);
        report.setEcdsaSigGroupsEphemeral(ecdsaSigGroupsEphemeral);
        report.setEcdsaSigGroupsTls13(ecdsaCertSigGroupsTls13);
    }
}
