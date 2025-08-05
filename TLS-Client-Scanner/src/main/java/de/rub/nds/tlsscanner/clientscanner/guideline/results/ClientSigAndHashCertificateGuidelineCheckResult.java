/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.Objects;
import java.util.Set;

public class ClientSigAndHashCertificateGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<SignatureAndHashAlgorithm> notRecommendedAlgorithms;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private ClientSigAndHashCertificateGuidelineCheckResult() {
        super(null, null);
        this.notRecommendedAlgorithms = null;
    }

    public ClientSigAndHashCertificateGuidelineCheckResult(
            GuidelineCheck check,
            GuidelineAdherence adherence,
            Set<SignatureAndHashAlgorithm> notRecommendedAlgorithms) {
        super(check, adherence);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing Information";
        }
        if (notRecommendedAlgorithms.isEmpty()) {
            return "Only listed X509SignatureAlgorithms are supported.";
        } else {
            return "The following X509SignatureAlgorithms were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<SignatureAndHashAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
