/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<NamedGroup> groups;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            return Pair.of(GuidelineCheckStatus.PASSED, "Is not ECDSA signature certificate.");
        }
        if (!(report.getPublicKey() instanceof CustomEcPublicKey)) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, "Public Key is not for EC.");
        }
        NamedGroup group = ((CustomEcPublicKey) report.getPublicKey()).getGroup();
        if (this.groups.contains(group)) {
            return Pair.of(GuidelineCheckStatus.FAILED, "Unrecommended Group " + group);
        }
        return Pair.of(GuidelineCheckStatus.PASSED, "Group is recommended.");
    }

    public List<NamedGroup> getGroups() {
        return groups;
    }

    public void setGroups(List<NamedGroup> groups) {
        this.groups = groups;
    }
}
