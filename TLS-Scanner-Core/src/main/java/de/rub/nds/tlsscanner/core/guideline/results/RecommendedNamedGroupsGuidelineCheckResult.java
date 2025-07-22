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
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Objects;
import java.util.Set;

public class RecommendedNamedGroupsGuidelineCheckResult extends GuidelineCheckResult {

    private Set<NamedGroup> notRecommendedButSupported;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RecommendedNamedGroupsGuidelineCheckResult() {
        super(null, null);
    }

    public RecommendedNamedGroupsGuidelineCheckResult(
            GuidelineCheck check, GuidelineAdherence adherence) {
        super(check, adherence);
    }

    public RecommendedNamedGroupsGuidelineCheckResult(
            GuidelineCheck check,
            GuidelineAdherence adherence,
            Set<NamedGroup> notRecommendedButSupported) {
        super(check, adherence);
        this.notRecommendedButSupported = notRecommendedButSupported;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing information.";
        }
        if (notRecommendedButSupported.isEmpty()) {
            return "Server passed the named groups check.";
        } else {
            return "The following groups were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedButSupported);
        }
    }

    public Set<NamedGroup> getNotRecommendedButSupported() {
        return notRecommendedButSupported;
    }
}
