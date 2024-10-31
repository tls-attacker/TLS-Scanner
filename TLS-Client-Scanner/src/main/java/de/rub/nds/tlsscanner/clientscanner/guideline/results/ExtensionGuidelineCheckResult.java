/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

public class ExtensionGuidelineCheckResult extends GuidelineCheckResult {

    private final List<ExtensionType> supportedExtensions;
    private final List<ExtensionType> affectedExtensions;

    public ExtensionGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            List<ExtensionType> supportedExtensions,
            List<ExtensionType> affectedExtensions) {
        super(checkName, adherence);
        this.supportedExtensions = supportedExtensions;
        this.affectedExtensions = affectedExtensions;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        for (ExtensionType extension : affectedExtensions) {
            builder.append(supportedExtensions.contains(extension)
                    ? "The client supports "
                    : "The client does not support ").append(extension).append("\n");
        }
        return builder.toString().stripTrailing();
    }

    public List<ExtensionType> getAffectedExtensions() {
        return affectedExtensions;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }
}
