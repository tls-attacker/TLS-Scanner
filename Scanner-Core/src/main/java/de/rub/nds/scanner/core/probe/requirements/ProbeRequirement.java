/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.List;
import java.util.stream.Collectors;

/** Represents a {@link Requirement} for required executed {@link ProbeType}s. */
public class ProbeRequirement<R extends ScanReport<R>> extends PrimitiveRequirement<R, ProbeType> {

    public ProbeRequirement(List<ProbeType> probes) {
        super(probes);
    }

    public ProbeRequirement(ProbeType... probes) {
        super(List.of(probes));
    }

    @Override
    public boolean evaluate(R report) {
        if (parameters.size() == 0) {
            return true;
        }
        for (ProbeType probe : parameters) {
            if (!report.isProbeAlreadyExecuted(probe)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format(
                "ProbeRequirement[%s]",
                parameters.stream().map(Object::toString).collect(Collectors.joining(", ")));
    }
}
