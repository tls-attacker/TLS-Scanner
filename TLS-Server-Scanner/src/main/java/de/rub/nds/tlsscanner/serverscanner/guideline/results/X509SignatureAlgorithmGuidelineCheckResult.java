/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.util.Objects;
import java.util.Set;

public class X509SignatureAlgorithmGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<X509SignatureAlgorithm> notRecommendedAlgorithms;

    public X509SignatureAlgorithmGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            Set<X509SignatureAlgorithm> notRecommendedAlgorithms) {
        super(checkName, adherence);
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

    public Set<X509SignatureAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }
}
