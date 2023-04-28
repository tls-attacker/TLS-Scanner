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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

import java.util.ArrayList;
import java.util.List;

/** Represents a {@link Requirement} of required supported {@link ProtocolVersion}s. */
public class ProtocolRequirement extends BooleanRequirement {
    /**
     * @param protocols the required {@link ProtocolVersion}s. Any amount possible.
     */
    public ProtocolRequirement(ProtocolVersion... protocols) {
        super(protocols);
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (parameters == null || parameters.length == 0) {
            return true;
        }
        boolean returnValue = false;
        missingParameters = new ArrayList<>();
        List<ProtocolVersion> protocolVersions =
                ((TlsScanReport) report).getSupportedProtocolVersions();
        if (protocolVersions != null && !protocolVersions.isEmpty()) {
            for (Enum<?> protocol : parameters) {
                if (protocolVersions.contains(protocol)) {
                    returnValue = true;
                } else {
                    missingParameters.add(protocol);
                }
            }
        } else {
            for (Enum<?> protocol : parameters) {
                missingParameters.add(protocol);
            }
        }
        return returnValue;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new ProtocolRequirement(
                                    this.missingParameters.toArray(
                                            new ProtocolVersion[this.missingParameters.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
