/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private NamedGroup namedGroup;

    public CertificateCurveGuidelineCheckResult(TestResult result, NamedGroup namedGroup) {
        super(result);
        this.namedGroup = namedGroup;
    }

    public CertificateCurveGuidelineCheckResult(TestResult result) {
        super(result);
    }

    @Override
    public String display() {
        return TestResult.TRUE.equals(getResult()) ? namedGroup + " is recommended."
            : namedGroup + " is not recommended.";
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }
}
