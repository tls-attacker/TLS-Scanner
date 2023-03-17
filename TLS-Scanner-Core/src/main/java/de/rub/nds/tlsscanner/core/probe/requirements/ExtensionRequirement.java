/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.BooleanRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.ArrayList;
import java.util.List;

/** Represents a {@link Requirement} for required {@link ExtensionType}s. */
public class ExtensionRequirement extends BooleanRequirement {
    /**
     * @param extensions the required {@link ExtensionType}s. Any amount possible.
     */
    public ExtensionRequirement(ExtensionType... extensions) {
        super(extensions);
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (parameters == null || parameters.length == 0) {
            return true;
        }
        boolean returnValue = false;
        missingParameters = new ArrayList<>();
        List<ExtensionType> extensionList = ((TlsScanReport) report).getSupportedExtensions();
        if (extensionList != null && !extensionList.isEmpty()) {
            for (Enum<?> extension : parameters) {
                if (extensionList.contains(extension)) {
                    returnValue = true;
                } else {
                    missingParameters.add(extension);
                }
            }
        } else {
            for (Enum<?> extension : parameters) {
                missingParameters.add(extension);
            }
        }
        return returnValue;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new ExtensionRequirement(
                                    this.missingParameters.toArray(
                                            new ExtensionType[this.missingParameters.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
