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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateAgilityGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.List;

public class CertificateAgilityGuidelineCheck extends GuidelineCheck {

    private CertificateAgilityGuidelineCheck() {
        super(null, null);
    }

    public CertificateAgilityGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CertificateAgilityGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition) {
        super(name, requirementLevel, condition);
    }

    @Override
    public GuidelineCheckResult evaluate(SiteReport report) {
        List<CertificateChain> chains = report.getCertificateChainList();
        if (chains == null || chains.size() < 2) {
            return new CertificateAgilityGuidelineCheckResult(TestResult.FALSE);
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
                return new CertificateAgilityGuidelineCheckResult(TestResult.TRUE);
            }
            if (firstKey != null && certReport.getPublicKey() instanceof CustomPublicKey) {
                if (firstKey != ((CustomPublicKey) certReport.getPublicKey()).keySize()) {
                    return new CertificateAgilityGuidelineCheckResult(TestResult.TRUE);
                }
            }
        }
        return new CertificateAgilityGuidelineCheckResult(TestResult.FALSE);
    }

    @Override
    public String getId() {
        return "CertificateAgility_" + getRequirementLevel();
    }

}
