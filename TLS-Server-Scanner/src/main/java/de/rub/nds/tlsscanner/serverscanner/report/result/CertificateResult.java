/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class CertificateResult extends ProbeResult {

    private Set<CertificateChain> certificates;
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;
    private List<NamedGroup> ecdsaSigGroupsStatic;
    private List<NamedGroup> ecdsaSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    public CertificateResult(Set<CertificateChain> certificates, List<NamedGroup> ecdsaPkGroupsStatic,
        List<NamedGroup> ecdsaPkGroupsEphemeral, List<NamedGroup> ecdsaSigGroupsStatic,
        List<NamedGroup> ecdsaSigGroupsEphemeral, List<NamedGroup> ecdsaPkGroupsTls13,
        List<NamedGroup> ecdsaCertSigGroupsTls13) {
        super(ProbeType.CERTIFICATE);
        this.certificates = certificates;
        this.ecdsaPkGroupsStatic = ecdsaPkGroupsStatic;
        this.ecdsaPkGroupsEphemeral = ecdsaPkGroupsEphemeral;
        this.ecdsaSigGroupsStatic = ecdsaSigGroupsStatic;
        this.ecdsaSigGroupsEphemeral = ecdsaSigGroupsEphemeral;
        this.ecdsaPkGroupsTls13 = ecdsaPkGroupsTls13;
        this.ecdsaCertSigGroupsTls13 = ecdsaCertSigGroupsTls13;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (certificates != null) {
            report.setCertificateChainList(new LinkedList<>(certificates));
        }
        report.setEcdsaPkGroupsStatic(ecdsaPkGroupsStatic);
        report.setEcdsaPkGroupsEphemeral(ecdsaPkGroupsEphemeral);
    }

}
