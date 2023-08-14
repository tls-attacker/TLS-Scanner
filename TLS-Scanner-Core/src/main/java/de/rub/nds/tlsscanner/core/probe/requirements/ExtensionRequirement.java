/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.PrimitiveRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.HashSet;
import java.util.List;

/** Represents a {@link Requirement} for required {@link ExtensionType}s. */
public class ExtensionRequirement<ReportT extends TlsScanReport>
        extends PrimitiveRequirement<ReportT, ExtensionType> {

    public ExtensionRequirement(List<ExtensionType> extensions) {
        super(extensions);
    }

    public ExtensionRequirement(ExtensionType... extensions) {
        super(List.of(extensions));
    }

    @Override
    public boolean evaluate(ReportT report) {
        if (parameters.size() == 0) {
            return true;
        }
        List<ExtensionType> extensionTypes = report.getSupportedExtensions();
        if (extensionTypes == null) {
            return false;
        }
        return new HashSet<>(extensionTypes).containsAll(parameters);
    }
}
