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
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.List;
import java.util.Objects;

public class RequiredNamedGroupsGuidelineCheckResult extends GuidelineCheckResult {

    private List<NamedGroup> requiredButNotSupported;
    private boolean onlyOneIsRequired;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RequiredNamedGroupsGuidelineCheckResult() {
        super(null, null);
    }

    public RequiredNamedGroupsGuidelineCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    public RequiredNamedGroupsGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<NamedGroup> requiredButNotSupported,
            boolean onlyOneIsRequired) {
        super(checkName, adherence);
        this.requiredButNotSupported = requiredButNotSupported;
        this.onlyOneIsRequired = onlyOneIsRequired;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing information.";
        }
        if (Objects.equals(GuidelineAdherence.ADHERED, getAdherence())) {
            return "Server passed the named groups check.";
        }
        if (onlyOneIsRequired) {
            return "Server is missing one of required groups:\n"
                    + Joiner.on('\n').join(requiredButNotSupported);
        } else {
            return "The following named groups are required by the guideline, but are not supported:\n"
                    + Joiner.on('\n').join(requiredButNotSupported);
        }
    }

    public List<NamedGroup> getRequiredButNotSupported() {
        return requiredButNotSupported;
    }

    public boolean isOnlyOneIsRequired() {
        return onlyOneIsRequired;
    }
}
