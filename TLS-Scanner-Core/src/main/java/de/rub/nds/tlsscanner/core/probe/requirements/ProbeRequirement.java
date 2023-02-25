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
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;

/** Represents a {@link Requirement} for required executed {@link TlsProbeType}s. */
public class ProbeRequirement extends BooleanRequirement {
    /**
     * @param probes the required {@link TlsProbeType}. Any amount possible.
     */
    public ProbeRequirement(TlsProbeType... probes) {
        super(probes);
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if ((parameters == null) || (parameters.length == 0)) {
            return true;
        }
        boolean returnValue = true;
        missingParameters = new ArrayList<>();
        for (Enum<?> probe : parameters) {
            if (report.isProbeAlreadyExecuted((TlsProbeType) probe) == false) {
                returnValue = false;
                missingParameters.add(probe);
            }
        }
        return returnValue;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new ProbeRequirement(
                                    this.missingParameters.toArray(
                                            new TlsProbeType[this.missingParameters.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
