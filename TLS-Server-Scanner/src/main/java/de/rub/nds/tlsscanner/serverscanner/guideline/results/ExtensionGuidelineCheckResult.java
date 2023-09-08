/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

public class ExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final boolean supported;
    private final ExtensionType requiredExtension;

    public ExtensionGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            boolean supported,
            ExtensionType requiredExtension) {
        super(checkName, adherence);
        this.supported = supported;
        this.requiredExtension = requiredExtension;
    }

    @Override
    public String toString() {
        return supported
                ? "The server supports " + this.requiredExtension
                : "The server does not support " + this.requiredExtension;
    }

    public ExtensionType getRequiredExtension() {
        return requiredExtension;
    }

    public boolean isSupported() {
        return supported;
    }
}
