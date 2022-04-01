/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;
import java.util.Set;

public class SignatureAndHashAlgorithmsCertificateGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<SignatureAndHashAlgorithm> notRecommendedAlgorithms;

    public SignatureAndHashAlgorithmsCertificateGuidelineCheckResult(TestResult result,
        Set<SignatureAndHashAlgorithm> notRecommendedAlgorithms) {
        super(result);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResult.UNCERTAIN, getResult())) {
            return "Missing Information";
        }
        if (notRecommendedAlgorithms.isEmpty()) {
            return "Only listed Signature and Hash Algorithms are supported.";
        } else {
            return "The following Signature and Hash Algorithms were supported but not recommended:\n"
                + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<SignatureAndHashAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
