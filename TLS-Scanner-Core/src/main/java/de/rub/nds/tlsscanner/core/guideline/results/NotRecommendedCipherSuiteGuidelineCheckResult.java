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
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.List;

public class NotRecommendedCipherSuiteGuidelineCheckResult extends GuidelineCheckResult {

    private final List<CipherSuite> notRecommendedButSupportedSuites;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private NotRecommendedCipherSuiteGuidelineCheckResult() {
        super(null, null);
        this.notRecommendedButSupportedSuites = null;
    }

    public NotRecommendedCipherSuiteGuidelineCheckResult(
            GuidelineCheck check,
            GuidelineAdherence adherence,
            List<CipherSuite> notRecommendedButSupportedSuites) {
        super(check, adherence);
        this.notRecommendedButSupportedSuites = notRecommendedButSupportedSuites;
    }

    @Override
    public String toString() {
        if (notRecommendedButSupportedSuites.isEmpty()) {
            return "None of the listed Cipher Suites is supported.";
        } else {
            return "The following Cipher Suites were supported contrary to the guideline:\n"
                    + Joiner.on('\n').join(notRecommendedButSupportedSuites);
        }
    }

    public List<CipherSuite> getNotRecommendedButSupportedSuites() {
        return notRecommendedButSupportedSuites;
    }
}
