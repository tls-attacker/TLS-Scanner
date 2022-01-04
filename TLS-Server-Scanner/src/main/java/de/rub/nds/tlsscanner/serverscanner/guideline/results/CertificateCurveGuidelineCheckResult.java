/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private boolean supported;
    private NamedGroup namedGroup;

    public CertificateCurveGuidelineCheckResult(TestResult result, boolean supported, NamedGroup namedGroup) {
        super(result);
        this.supported = supported;
        this.namedGroup = namedGroup;
    }

    public CertificateCurveGuidelineCheckResult(TestResult result) {
        super(result);
    }

    @Override
    public String display() {
        return supported ? namedGroup + " is recommended." : namedGroup + " is not recommended.";
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    public boolean isSupported() {
        return supported;
    }
}
