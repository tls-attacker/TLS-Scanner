/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;
import java.util.Set;

public class RecommendedHashAlgorithmsGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<HashAlgorithm> supportedButNotRecommendedAlgorithms;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RecommendedHashAlgorithmsGuidelineCheckResult() {
        super(null, null);
        this.supportedButNotRecommendedAlgorithms = null;
    }

    public RecommendedHashAlgorithmsGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            Set<HashAlgorithm> supportedButNotRecommendedAlgorithms) {
        super(checkName, adherence);
        this.supportedButNotRecommendedAlgorithms = supportedButNotRecommendedAlgorithms;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing Information";
        }
        if (supportedButNotRecommendedAlgorithms.isEmpty()) {
            return "Only listed Hash Algorithms are supported.";
        } else {
            return "The following Hash Algorithms were supported but are not explicitly recommended by the guideline:\n"
                    + Joiner.on('\n').join(supportedButNotRecommendedAlgorithms);
        }
    }

    public Set<HashAlgorithm> getSupportedButNotRecommendedAlgorithms() {
        return supportedButNotRecommendedAlgorithms;
    }
}
