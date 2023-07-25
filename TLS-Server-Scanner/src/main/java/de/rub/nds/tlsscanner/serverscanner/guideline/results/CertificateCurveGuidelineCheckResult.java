/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;

public class CertificateCurveGuidelineCheckResult extends GuidelineCheckResult {

    private boolean supported;
    private NamedEllipticCurveParameters namedEllipticCurveParameters;

    public CertificateCurveGuidelineCheckResult(
            TestResult result, boolean supported, NamedEllipticCurveParameters namedEllipticCurveParameters) {
        super(result);
        this.supported = supported;
        this.namedEllipticCurveParameters = namedEllipticCurveParameters;
    }

    public CertificateCurveGuidelineCheckResult(TestResult result) {
        super(result);
    }

    @Override
    public String display() {
        return supported ? namedEllipticCurveParameters + " is recommended." : namedEllipticCurveParameters + " is not recommended.";
    }

    public NamedEllipticCurveParameters getNamedEllipticCurveParameters() {
        return namedEllipticCurveParameters;
    }

    public boolean isSupported() {
        return supported;
    }
}
