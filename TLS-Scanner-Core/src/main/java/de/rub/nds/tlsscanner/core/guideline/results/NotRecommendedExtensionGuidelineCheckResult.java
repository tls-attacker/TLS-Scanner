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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import java.util.List;

public class NotRecommendedExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final List<ExtensionType> notRecommendedButSupportedExtensions;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private NotRecommendedExtensionGuidelineCheckResult() {
        super(null, null);
        this.notRecommendedButSupportedExtensions = null;
    }

    public NotRecommendedExtensionGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<ExtensionType> notRecommendedButSupportedExtensions) {
        super(checkName, adherence);
        this.notRecommendedButSupportedExtensions = notRecommendedButSupportedExtensions;
    }

    @Override
    public String toString() {
        if (notRecommendedButSupportedExtensions.isEmpty()) {
            return "None of the listed Extensions is supported.";
        } else {
            return "The following extensions were supported contrary to the guideline:\n"
                    + Joiner.on('\n').join(notRecommendedButSupportedExtensions);
        }
    }

    public List<ExtensionType> getNotRecommendedButSupportedExtensions() {
        return notRecommendedButSupportedExtensions;
    }
}
