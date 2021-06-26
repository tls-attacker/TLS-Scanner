/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * Ordered according to NIST.SP.800-57pt1r5.
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
 */
public class HashAlgorithmStrengthCheck extends CertificateGuidelineCheck {

    private static final Map<HashAlgorithm, Integer> STRENGTH = new HashMap<HashAlgorithm, Integer>() {
        {
            put(HashAlgorithm.SHA1, 80);
            put(HashAlgorithm.SHA224, 112);
            put(HashAlgorithm.SHA256, 128);
            put(HashAlgorithm.SHA384, 192);
            put(HashAlgorithm.SHA512, 256);
        }
    };

    private HashAlgorithm min;

    @Override
    public GuidelineCheckStatus evaluateChain(CertificateChain chain, GuidelineCheckResult result) {
        Comparator<HashAlgorithm> comparator = Comparator.comparing(STRENGTH::get);
        for (CertificateReport report : chain.getCertificateReportList()) {
            int comparison = comparator.compare(report.getSignatureAndHashAlgorithm().getHashAlgorithm(), this.min);
            if (comparison < 0) {
                result.append(report.getSignatureAndHashAlgorithm().getHashAlgorithm() + " is too weak.");
                return GuidelineCheckStatus.FAILED;
            }
        }
        result.append("Used Hash Algorithms are strong enough.");
        return GuidelineCheckStatus.PASSED;
    }

    public HashAlgorithm getMin() {
        return min;
    }

    public void setMin(HashAlgorithm min) {
        this.min = min;
    }
}
