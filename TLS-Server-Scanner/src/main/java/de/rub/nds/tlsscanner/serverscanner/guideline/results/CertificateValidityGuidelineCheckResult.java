/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.Objects;

public class CertificateValidityGuidelineCheckResult extends GuidelineCheckResult {

    private final int maximumValidity;
    private final long actualValidity;

    public CertificateValidityGuidelineCheckResult(TestResult result, int expectedResult, long actualResult) {
        super(result);
        this.maximumValidity = expectedResult;
        this.actualValidity = actualResult;
    }

    @Override
    public String display() {
        return String.format("Certificate Validity %d days is %s. (Max %d days.)", actualValidity,
            Objects.equals(TestResult.TRUE, getResult()) ? "okay" : "too long", maximumValidity);
    }

    public int getMaximumValidity() {
        return maximumValidity;
    }

    public long getActualValidity() {
        return actualValidity;
    }
}
