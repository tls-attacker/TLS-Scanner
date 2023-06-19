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
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/** A simple requirement combining two or more requirements with a logical AND. */
public final class AndRequirement<R extends ScanReport<R>> extends LogicalRequirement<R> {

    private final List<Requirement<R>> requirements;

    public AndRequirement(List<Requirement<R>> requirements) {
        this.requirements = Collections.unmodifiableList(requirements);
    }

    @Override
    public boolean evaluate(R report) {
        return requirements.stream().allMatch(requirement -> requirement.evaluate(report));
    }

    @Override
    public List<Requirement<R>> getUnfulfilledRequirements(R report) {
        return requirements.stream()
                .filter(requirement -> !requirement.evaluate(report))
                .flatMap(requirement -> requirement.getUnfulfilledRequirements(report).stream())
                .collect(Collectors.toUnmodifiableList());
    }

    @Override
    public List<Requirement<R>> getContainedRequirements() {
        return requirements;
    }

    @Override
    public String toString() {
        return String.format(
                "(%s)",
                requirements.stream().map(Object::toString).collect(Collectors.joining(" and ")));
    }
}
