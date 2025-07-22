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
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;
import java.util.Set;

public class NotRecommendedHashAlgorithmsGuidelineCheckResult extends GuidelineCheckResult {

    private final Set<HashAlgorithm> notRecommendedButSupportedAlgorithms;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private NotRecommendedHashAlgorithmsGuidelineCheckResult() {
        super(null, null);
        this.notRecommendedButSupportedAlgorithms = null;
    }

    public NotRecommendedHashAlgorithmsGuidelineCheckResult(
            GuidelineCheck check,
            GuidelineAdherence adherence,
            Set<HashAlgorithm> notRecommendedButSupportedAlgorithms) {
        super(check, adherence);
        this.notRecommendedButSupportedAlgorithms = notRecommendedButSupportedAlgorithms;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing Information";
        }
        if (notRecommendedButSupportedAlgorithms.isEmpty()) {
            return "None of the listed Hash Algorithms is supported.";
        } else {
            return "The following Hash Algorithms were supported contrary to the guideline:\n"
                    + Joiner.on('\n').join(notRecommendedButSupportedAlgorithms);
        }
    }

    public Set<HashAlgorithm> getNotRecommendedButSupportedAlgorithms() {
        return notRecommendedButSupportedAlgorithms;
    }
}
