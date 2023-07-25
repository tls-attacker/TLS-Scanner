/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.Objects;
import java.util.Set;

public class SignatureAndHashAlgorithmsCertificateGuidelineCheckResult
        extends GuidelineCheckResult {

    private final Set<X509SignatureAlgorithm> notRecommendedAlgorithms;

    public SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(
            TestResult result, Set<X509SignatureAlgorithm> notRecommendedAlgorithms) {
        super(result);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResults.UNCERTAIN, getResult())) {
            return "Missing Information";
        }
        if (notRecommendedAlgorithms.isEmpty()) {
            return "Only listed Signature and Hash Algorithms are supported.";
        } else {
            return "The following Signature and Hash Algorithms were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<X509SignatureAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
