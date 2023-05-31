/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.LogicRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Represents a {@link Requirement} for required negated Requirements. If the contained Requirement
 * evaluates to true, this Requirement evaluates to false and vice versa.
 */
public class NotRequirement extends LogicRequirement {
    /**
     * @param notRequirement the {@link Requirement} to negate.
     */
    public NotRequirement(Requirement notRequirement) {
        super(new Requirement[] {notRequirement});
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (parameters[0] == null) {
            return true;
        }
        return !parameters[0].evaluate(report);
    }

    @Override
    public String toString() {
        return "(not "
                + Arrays.stream(parameters).map(Requirement::name).collect(Collectors.joining(","))
                + ")";
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(new NotRequirement(parameters[0])), report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
