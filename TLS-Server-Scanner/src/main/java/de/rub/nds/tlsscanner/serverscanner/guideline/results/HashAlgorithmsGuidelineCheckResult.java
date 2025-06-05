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
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;
import java.util.Set;

public class HashAlgorithmsGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<HashAlgorithm> notRecommendedAlgorithms;
    // If false HashAlgorithmsGuidelineCheck checked if the provided algorithms are NOT supported.
    private boolean recommended;

    public HashAlgorithmsGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            Set<HashAlgorithm> notRecommendedAlgorithms,
            boolean recommended) {
        super(checkName, adherence);
        this.notRecommendedAlgorithms = notRecommendedAlgorithms;
        this.recommended = recommended;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing Information";
        }
        if (notRecommendedAlgorithms.isEmpty()) {
            if (recommended) return "Only listed Hash Algorithms are supported.";
            return "None of the listed Hash Algorithms is supported.";
        } else {
            return "The following Hash Algorithms were supported contrary to the guideline:\n"
                    + Joiner.on('\n').join(notRecommendedAlgorithms);
        }
    }

    public Set<HashAlgorithm> getNotRecommendedAlgorithms() {
        return notRecommendedAlgorithms;
    }

    public boolean isRecommended() {
        return recommended;
    }
}
