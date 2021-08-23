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

public class CertificateAgilityGuidelineCheckResult extends GuidelineCheckResult {

    public CertificateAgilityGuidelineCheckResult(TestResult result) {
        super(result);
    }

    @Override
    public String display() {
        return TestResult.TRUE.equals(getResult()) ? "Server supports multiple Certificate types."
            : "Server does not support multiple Certificate types.";
    }
}
