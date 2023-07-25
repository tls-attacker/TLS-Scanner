/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import java.util.Objects;
import java.util.Set;

import com.google.common.base.Joiner;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;

public class HashAlgorithmsGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<HashAlgorithm> notRecommendedAlgorithms;

    public HashAlgorithmsGuidelineCheckResult(
            TestResult result, Set<HashAlgorithm> notRecommendedAlgorithms) {
        super(result);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResults.UNCERTAIN, getResult())) {
            return "Missing Information";
        }
        if (notRecommendedAlgorithms.isEmpty()) {
            return "Only listed Hash Algorithms are supported.";
        } else {
            return "The following Hash Algorithms were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<HashAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
