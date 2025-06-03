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

public class CertificateNameGuidelineCheckResult extends GuidelineCheckResult {

    String rdn;
    String reason;

    public CertificateNameGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence, String rdn, String reason) {
        super(checkName, adherence);
        this.rdn = rdn;
        this.reason = reason;
    }

    @Override
    public String toString() {
        return String.format("Certificate Name for RDN %s is invalid: %s", rdn, reason);
    }

    public String getReason() {
        return reason;
    }

    public String getRdn() {
        return rdn;
    }
}
