/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CertificateResult extends ProbeResult {

    private List<CertificateChain> certificates;
    private List<NamedGroup> ecdsaPkGroupsStatic;
    private List<NamedGroup> ecdsaPkGroupsEphemeral;
    private List<NamedGroup> ecdsaPkGroupsTls13;
    private List<NamedGroup> ecdsaSigGroupsStatic;
    private List<NamedGroup> ecdsaSigGroupsEphemeral;
    private List<NamedGroup> ecdsaCertSigGroupsTls13;

    public CertificateResult(List<CertificateChain> certificates, List<NamedGroup> ecdsaPkGroupsStatic,
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
        report.setCertificateChainList(certificates);
        report.setEcdsaPkGroupsStatic(ecdsaPkGroupsStatic);
        report.setEcdsaPkGroupsEphemeral(ecdsaPkGroupsEphemeral);
    }

}
