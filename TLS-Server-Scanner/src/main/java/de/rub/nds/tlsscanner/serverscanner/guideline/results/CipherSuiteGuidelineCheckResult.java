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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.List;

public class CipherSuiteGuidelineCheckResult extends GuidelineCheckResult {

    private final List<CipherSuite> nonRecommendedSuites;

    public CipherSuiteGuidelineCheckResult(TestResult result, List<CipherSuite> nonRecommendedSuites) {
        super(result);
        this.nonRecommendedSuites = nonRecommendedSuites;
    }

    @Override
    public String display() {
        if (TestResult.TRUE.equals(getResult())) {
            return "Only listed Cipher Suites are supported.";
        } else {
            return "The following Cipher Suites were supported but not recommended:\n"
                + Joiner.on('\n').join(nonRecommendedSuites);
        }
    }

    public List<CipherSuite> getNonRecommendedSuites() {
        return nonRecommendedSuites;
    }
}
