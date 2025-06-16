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
import java.util.Objects;

public class ExtendedKeyUsageCertificateCheckResult extends GuidelineCheckResult {

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private ExtendedKeyUsageCertificateCheckResult() {
        super(null, null);
    }

    public ExtendedKeyUsageCertificateCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    @Override
    public String toString() {
        return Objects.equals(GuidelineAdherence.ADHERED, getAdherence())
                ? "Certificate has extended key usage for server auth."
                : "Certificate is missing extended key usage for server auth.";
    }
}
