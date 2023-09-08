/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private boolean supported;
    private NamedGroup namedGroup;

    public CertificateCurveGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            boolean supported,
            NamedGroup namedGroup) {
        super(checkName, adherence);
        this.supported = supported;
        this.namedGroup = namedGroup;
    }

    public CertificateCurveGuidelineCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    @Override
    public String toString() {
        return supported ? namedGroup + " is recommended." : namedGroup + " is not recommended.";
    }

    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    public boolean isSupported() {
        return supported;
    }
}
