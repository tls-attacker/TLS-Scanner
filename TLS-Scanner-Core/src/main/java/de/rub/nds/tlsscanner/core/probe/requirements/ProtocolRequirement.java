/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.scanner.core.probe.requirements.BooleanRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/** Represents a {@link Requirement} of required supported {@link ProtocolVersion}s. */
public class ProtocolRequirement extends BooleanRequirement {
    private final ProtocolVersion[] protocols;
    private List<ProtocolVersion> missing;

    /**
     * @param protocols the required {@link ProtocolVersion}s. Any amount possible.
     */
    public ProtocolRequirement(ProtocolVersion... protocols) {
        super();
        this.protocols = protocols;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if ((protocols == null) || (protocols.length == 0)) {
            return true;
        }
        boolean returnValue = false;
        missing = new ArrayList<>();
        List<ProtocolVersion> protocolVersions =
                ((TlsScanReport) report).getSupportedProtocolVersions();
        if (protocolVersions != null && !protocolVersions.isEmpty()) {
            for (ProtocolVersion protocol : protocols) {
                if (protocolVersions.contains(protocol)) {
                    returnValue = true;
                } else {
                    missing.add(protocol);
                }
            }
        } else {
            for (ProtocolVersion protocol : protocols) {
                missing.add(protocol);
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
                                    this.missing.toArray(
                                            new ProtocolVersion[this.missing.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
