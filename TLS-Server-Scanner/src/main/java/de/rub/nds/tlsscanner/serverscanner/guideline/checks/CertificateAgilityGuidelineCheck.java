/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.List;

public class CertificateAgilityGuidelineCheck extends ConditionalGuidelineCheck {

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        List<CertificateChain> chains = report.getCertificateChainList();
        if (chains == null || chains.size() < 2) {
            result.update(GuidelineCheckStatus.FAILED, "Server does not have multiple Certificates.");
            return;
        }
        CertificateReport firstReport = chains.get(0).getCertificateReportList().get(0);
        SignatureAndHashAlgorithm firstAlg = firstReport.getSignatureAndHashAlgorithm();
        Integer firstKey = null;
        if (firstReport.getPublicKey() instanceof CustomPublicKey) {
            firstKey = ((CustomPublicKey) firstReport.getPublicKey()).keySize();
        }
        for (int i = 1; i < chains.size(); i++) {
            CertificateChain chain = chains.get(i);
            CertificateReport certReport = chain.getCertificateReportList().get(0);
            if (!firstAlg.equals(certReport.getSignatureAndHashAlgorithm())) {
                result.update(GuidelineCheckStatus.PASSED, "Server supports multiple Algorithms.");
                return;
            }
            if (firstKey != null && certReport.getPublicKey() instanceof CustomPublicKey) {
                if (firstKey != ((CustomPublicKey) certReport.getPublicKey()).keySize()) {
                    result.update(GuidelineCheckStatus.PASSED, "Server supports multiple Key Sizes.");
                    return;
                }
            }
        }
        result.update(GuidelineCheckStatus.FAILED, "Server does not support multiple Certificate types.");
    }
}
