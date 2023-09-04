/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.HashAlgorithmStrengthCheckResult;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Comparator;

/**
 * Ordered according to NIST.SP.800-57pt1r5.
 *
 * @see <a
 *     href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class HashAlgorithmStrengthCheck extends CertificateGuidelineCheck {

    private HashAlgorithm minimumStrength;

    private HashAlgorithmStrengthCheck() {
        super(null, null);
    }

    public HashAlgorithmStrengthCheck(
            String name, RequirementLevel requirementLevel, HashAlgorithm minimumStrength) {
        super(name, requirementLevel);
        this.minimumStrength = minimumStrength;
    }

    public HashAlgorithmStrengthCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            HashAlgorithm minimumStrength) {
        super(name, requirementLevel, onlyOneCertificate);
        this.minimumStrength = minimumStrength;
    }

    public HashAlgorithmStrengthCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            HashAlgorithm minimumStrength) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.minimumStrength = minimumStrength;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        Comparator<HashAlgorithm> comparator =
                Comparator.comparing(HashAlgorithm::getSecurityStrength);
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (report.isTrustAnchor()) {
                continue;
            }
            HashAlgorithm hashAlgorithm = report.getHashAlgorithm();
            int comparison = comparator.compare(hashAlgorithm, this.minimumStrength);
            if (comparison < 0) {
                return new HashAlgorithmStrengthCheckResult(
                        getName(), GuidelineAdherence.VIOLATED, hashAlgorithm);
            }
        }
        return new HashAlgorithmStrengthCheckResult(getName(), GuidelineAdherence.ADHERED, null);
    }

    @Override
    public String toString() {
        return "HashAlgorithmStrength_" + getRequirementLevel() + "_" + minimumStrength;
    }

    public HashAlgorithm getMinimumStrength() {
        return minimumStrength;
    }
}
