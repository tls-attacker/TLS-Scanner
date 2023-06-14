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

public final class NotRequirement<R extends ScanReport<R>> extends LogicalRequirement<R> {

    private final Requirement<R> requirement;

    public NotRequirement(Requirement<R> requirement) {
        this.requirement = requirement;
    }

    @Override
    public boolean evaluate(R report) {
        return requirement != null && !requirement.evaluate(report);
    }

    @Override
    public List<Requirement<R>> getContainedRequirements() {
        return List.of(requirement);
    }

    @Override
    public String toString() {
        return String.format("not(%s)", requirement);
    }
}
