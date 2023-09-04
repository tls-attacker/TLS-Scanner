/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private boolean supported;
    private NamedEllipticCurveParameters namedEllipticCurveParameters;

    public CertificateCurveGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            boolean supported,
            NamedEllipticCurveParameters namedEllipticCurveParameters) {
        super(checkName, adherence);
        this.supported = supported;
        this.namedEllipticCurveParameters = namedEllipticCurveParameters;
    }

    public CertificateCurveGuidelineCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    @Override
    public String toString() {
        return supported
                ? namedEllipticCurveParameters + " is recommended."
                : namedEllipticCurveParameters + " is not recommended.";
    }

    public NamedEllipticCurveParameters getNamedEllipticCurveParameters() {
        return namedEllipticCurveParameters;
    }

    public boolean isSupported() {
        return supported;
    }
}
