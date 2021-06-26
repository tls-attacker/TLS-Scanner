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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.List;

public class CertificateCurveGuidelineCheck extends CertificateGuidelineCheck {

    private List<NamedGroup> groups;

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        if (!SignatureAlgorithm.ECDSA.equals(report.getSignatureAndHashAlgorithm().getSignatureAlgorithm())) {
            result.append("Is not ECDSA signature certificate.");
            return GuidelineCheckStatus.PASSED;
        }
        if (!(report.getPublicKey() instanceof CustomEcPublicKey)) {
            result.append("Public Key is not for EC.");
            return GuidelineCheckStatus.UNCERTAIN;
        }
        NamedGroup group = ((CustomEcPublicKey) report.getPublicKey()).getGroup();
        if (!this.groups.contains(group)) {
            result.append("Unrecommended Group " + group);
            return GuidelineCheckStatus.FAILED;
        }
        result.append("Group is recommended.");
        return GuidelineCheckStatus.PASSED;
    }

    public List<NamedGroup> getGroups() {
        return groups;
    }

    public void setGroups(List<NamedGroup> groups) {
        this.groups = groups;
    }
}
