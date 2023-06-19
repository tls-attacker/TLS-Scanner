/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;
import java.util.List;

/**
 * A simple requirement which always evaluates to false. This may be used in probes to prevent
 * execution.
 *
 * @see FulfilledRequirement
 */
public final class UnfulfillableRequirement<R extends ScanReport<R>> extends Requirement<R> {

    @Override
    public boolean evaluate(R report) {
        return false;
    }

    @Override
    public List<Requirement<R>> getUnfulfilledRequirements(R report) {
        return List.of(this);
    }

    @Override
    public String toString() {
        return "UnfulfillableRequirement";
    }
}
