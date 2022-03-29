/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.HashAlgorithmStrengthCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.Comparator;

/**
 * Ordered according to NIST.SP.800-57pt1r5.
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
 */
public class HashAlgorithmStrengthCheck extends CertificateGuidelineCheck {

    private HashAlgorithm minimumStrength;

    private HashAlgorithmStrengthCheck() {
        super(null, null);
    }

    public HashAlgorithmStrengthCheck(String name, RequirementLevel requirementLevel, HashAlgorithm minimumStrength) {
        super(name, requirementLevel);
        this.minimumStrength = minimumStrength;
    }

    public HashAlgorithmStrengthCheck(String name, RequirementLevel requirementLevel, boolean onlyOneCertificate,
        HashAlgorithm minimumStrength) {
        super(name, requirementLevel, onlyOneCertificate);
        this.minimumStrength = minimumStrength;
    }

    public HashAlgorithmStrengthCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        boolean onlyOneCertificate, HashAlgorithm minimumStrength) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.minimumStrength = minimumStrength;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        Comparator<HashAlgorithm> comparator = Comparator.comparing(HashAlgorithm::getSecurityStrength);
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (report.isTrustAnchor()) {
                continue;
            }
            HashAlgorithm hashAlgorithm = report.getSignatureAndHashAlgorithm().getHashAlgorithm();
            int comparison = comparator.compare(hashAlgorithm, this.minimumStrength);
            if (comparison < 0) {
                return new HashAlgorithmStrengthCheckResult(TestResult.FALSE, hashAlgorithm);
            }
        }
        return new HashAlgorithmStrengthCheckResult(TestResult.TRUE, null);
    }

    @Override
    public String getId() {
        return "HashAlgorithmStrength_" + getRequirementLevel() + "_" + minimumStrength;
    }

    public HashAlgorithm getMinimumStrength() {
        return minimumStrength;
    }
}
