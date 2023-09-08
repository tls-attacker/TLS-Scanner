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

public class CertificateValidityGuidelineCheckResult extends GuidelineCheckResult {

    private final int maximumValidity;
    private final long actualValidity;

    public CertificateValidityGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence, int expectedResult, long actualResult) {
        super(checkName, adherence);
        this.maximumValidity = expectedResult;
        this.actualValidity = actualResult;
    }

    @Override
    public String toString() {
        return String.format(
                "Certificate Validity is %d. (Max %d days.)", actualValidity, maximumValidity);
    }

    public int getMaximumValidity() {
        return maximumValidity;
    }

    public long getActualValidity() {
        return actualValidity;
    }
}
