/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateAgilityGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Checks if the server support the use of multiple server certificates with their associated
 * private keys to support algorithm and key size agility.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateAgilityGuidelineCheck extends GuidelineCheck<ServerReport> {

    private CertificateAgilityGuidelineCheck() {
        super(null, null);
    }

    public CertificateAgilityGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CertificateAgilityGuidelineCheck(
            String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        super(name, requirementLevel, condition);
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        @SuppressWarnings("unchecked")
        List<CertificateChainReport> chains = report.getCertificateChainList();
        if (chains == null || chains.size() < 2) {
            return new CertificateAgilityGuidelineCheckResult(
                    getName(), GuidelineAdherence.VIOLATED);
        }
        CertificateReport firstReport = chains.get(0).getCertificateReportList().get(0);
        ObjectIdentifier firstAlg = firstReport.getSignatureAndHashAlgorithmOid();
        Integer firstKey = firstReport.getPublicKey().length();

        for (int i = 1; i < chains.size(); i++) {
            CertificateChainReport chain = chains.get(i);
            CertificateReport certReport = chain.getCertificateReportList().get(0);
            if (!firstAlg.equals(certReport.getSignatureAndHashAlgorithmOid())) {
                return new CertificateAgilityGuidelineCheckResult(
                        getName(), GuidelineAdherence.ADHERED);
            }
            if (firstKey != certReport.getPublicKey().length()) {
                if (firstKey != ((PublicKeyContainer) certReport.getPublicKey()).length()) {
                    return new CertificateAgilityGuidelineCheckResult(
                            getName(), GuidelineAdherence.ADHERED);
                }
            }
        }
        return new CertificateAgilityGuidelineCheckResult(getName(), GuidelineAdherence.VIOLATED);
    }

    @Override
    public String toString() {
        return "CertificateAgility_" + getRequirementLevel();
    }
}
