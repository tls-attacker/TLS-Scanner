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
import de.rub.nds.x509attacker.constants.X509NamedCurve;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private boolean supported;
    private X509NamedCurve namedCurve;

    public CertificateCurveGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            boolean supported,
            X509NamedCurve namedEllipticCurveParameters) {
        super(checkName, adherence);
        this.supported = supported;
        this.namedCurve = namedEllipticCurveParameters;
    }

    public CertificateCurveGuidelineCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    @Override
    public String toString() {
        return supported ? namedCurve + " is recommended." : namedCurve + " is not recommended.";
    }

    public X509NamedCurve getNamedCurve() {
        return namedCurve;
    }

    public boolean isSupported() {
        return supported;
    }
}
