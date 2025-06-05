/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.List;

public class CipherSuiteGuidelineCheckResult extends GuidelineCheckResult {

    private final List<CipherSuite> notRecommendedSuites;
    // If false CipherSuiteGuidelineCheck checked if the provided cipher suites are NOT supported.
    private boolean recommended;

    public CipherSuiteGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<CipherSuite> notRecommendedSuites,
            boolean recommended) {
        super(checkName, adherence);
        this.notRecommendedSuites = notRecommendedSuites;
        this.recommended = recommended;
    }

    @Override
    public String toString() {
        if (notRecommendedSuites.isEmpty()) {
            if (recommended) return "Only listed Cipher Suites are supported.";
            return "None of the listed Cipher Suites is supported.";
        } else {
            return "The following Cipher Suites were supported contrary to the guideline:\n"
                    + Joiner.on('\n').join(notRecommendedSuites);
        }
    }

    public List<CipherSuite> getNotRecommendedSuites() {
        return notRecommendedSuites;
    }

    public boolean isRecommended() {
        return recommended;
    }
}
