/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.List;

public class CipherSuiteGuidelineCheckResult extends GuidelineCheckResult {

    private final List<CipherSuite> notRecommendedSuites;

    public CipherSuiteGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<CipherSuite> notRecommendedSuites) {
        super(checkName, adherence);
        this.notRecommendedSuites = notRecommendedSuites;
    }

    @Override
    public String toString() {
        if (notRecommendedSuites.isEmpty()) {
            return "Only listed Cipher Suites are supported.";
        } else {
            return "The following Cipher Suites were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedSuites);
        }
    }

    public List<CipherSuite> getNotRecommendedSuites() {
        return notRecommendedSuites;
    }
}
