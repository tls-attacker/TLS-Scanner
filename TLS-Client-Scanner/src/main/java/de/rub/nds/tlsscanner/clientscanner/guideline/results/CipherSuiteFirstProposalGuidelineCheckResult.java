/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;

public class CipherSuiteFirstProposalGuidelineCheckResult extends GuidelineCheckResult {

    public CipherSuiteFirstProposalGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    @Override
    public String toString() {
        return Objects.equals(GuidelineAdherence.ADHERED, getAdherence())
                ? "Client uses TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as the first proposal for TLS 1.2."
                : "Client does not use TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as the first proposal for TLS 1.2.";
    }
}
