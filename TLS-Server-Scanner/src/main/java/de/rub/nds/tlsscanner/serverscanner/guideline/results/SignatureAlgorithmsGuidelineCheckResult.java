/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.Objects;
import java.util.Set;

public class SignatureAlgorithmsGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<SignatureAlgorithm> notRecommendedAlgorithms;

    public SignatureAlgorithmsGuidelineCheckResult(TestResult result,
        Set<SignatureAlgorithm> notRecommendedAlgorithms) {
        super(result);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResult.UNCERTAIN, getResult())) {
            return "Missing Information";
        }
        if (Objects.equals(TestResult.TRUE, getResult())) {
            return "Only listed Signature Algorithms are supported.";
        } else {
            return "The following Signature Algorithms were supported but not recommended:\n"
                + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<SignatureAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
