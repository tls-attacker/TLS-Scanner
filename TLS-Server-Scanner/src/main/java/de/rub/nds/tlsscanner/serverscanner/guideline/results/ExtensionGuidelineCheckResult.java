/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;

public class ExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final boolean supported;
    private final ExtensionType requiredExtension;

    public ExtensionGuidelineCheckResult(
            TestResult result, boolean supported, ExtensionType requiredExtension) {
        super(result);
        this.supported = supported;
        this.requiredExtension = requiredExtension;
    }

    @Override
    public String display() {
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
