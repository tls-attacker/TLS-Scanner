/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import java.util.Objects;

public class KeyUsageCertificateCheckResult extends GuidelineCheckResult {

    private final boolean supported;
    private final String keyUsage;

    public KeyUsageCertificateCheckResult(TestResult result, boolean supported, String keyUsage) {
        super(result);
        this.supported = supported;
        this.keyUsage = keyUsage;
    }

    @Override
    public String display() {
        return Objects.equals(TestResults.TRUE, getResult()) ? "Certificate has correct key usage " + getKeyUsage()
            : "Certificate is missing key usage " + getKeyUsage();
    }

    public String getKeyUsage() {
        return keyUsage == null ? "" : keyUsage;
    }

    public boolean isSupported() {
        return supported;
    }
}
