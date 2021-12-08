/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;

import java.util.Objects;

public class ExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final boolean supported;
    private final ExtensionType requiredExtension;

    public ExtensionGuidelineCheckResult(TestResult result, boolean supported, ExtensionType requiredExtension) {
        super(result);
        this.supported = supported;
        this.requiredExtension = requiredExtension;
    }

    @Override
    public String display() {
        return supported ? "The server supports " + this.requiredExtension
            : "The server does not support " + this.requiredExtension;
    }

    public ExtensionType getRequiredExtension() {
        return requiredExtension;
    }

    public boolean isSupported() {
        return supported;
    }
}
