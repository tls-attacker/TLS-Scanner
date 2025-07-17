/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.List;

public class RecommendedCipherSuiteGuidelineCheckResult extends GuidelineCheckResult {

    private final List<CipherSuite> supportedButNotRecommendedSuites;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RecommendedCipherSuiteGuidelineCheckResult() {
        super(null, null);
        this.supportedButNotRecommendedSuites = null;
    }

    public RecommendedCipherSuiteGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<CipherSuite> supportedButNotRecommendedSuites) {
        super(checkName, adherence);
        this.supportedButNotRecommendedSuites = supportedButNotRecommendedSuites;
    }

    @Override
    public String toString() {
        if (supportedButNotRecommendedSuites.isEmpty()) {
            return "Only listed Cipher Suites are supported.";
        } else {
            return "The following Cipher Suites were supported but are not explicitly recommended by the guideline:\n"
                    + Joiner.on('\n').join(supportedButNotRecommendedSuites);
        }
    }

    public List<CipherSuite> getSupportedButNotRecommendedSuites() {
        return supportedButNotRecommendedSuites;
    }
}
