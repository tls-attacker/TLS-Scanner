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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import java.util.List;

public class RequiredExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final List<ExtensionType> requiredButNotSupported;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RequiredExtensionGuidelineCheckResult() {
        super(null, null);
        this.requiredButNotSupported = null;
    }

    public RequiredExtensionGuidelineCheckResult(
            GuidelineCheck check,
            GuidelineAdherence adherence,
            List<ExtensionType> requiredButNotSupported) {
        super(check, adherence);
        this.requiredButNotSupported = requiredButNotSupported;
    }

    @Override
    public String toString() {
        if (requiredButNotSupported.isEmpty()) {
            return "All required extensions are supported.";
        } else {
            return "The following extensions are required by the guideline, but are not supported:\n"
                    + Joiner.on('\n').join(requiredButNotSupported);
        }
    }

    public List<ExtensionType> getRequiredButNotSupported() {
        return requiredButNotSupported;
    }
}
