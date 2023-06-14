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
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class to represent requirements of probes which can be evaluated for fulfillness, which
 * return their respective "requirement", and which allow to retrieve the not yet fulfilled
 * requirements.
 */
public abstract class Requirement<R extends ScanReport<R>> {

    /**
     * Evaluates this requirement.
     *
     * @param report the {@link ScanReport}.
     * @return result of the evaluation of this requirement as boolean.
     */
    public abstract boolean evaluate(R report);

    /**
     * Creates a new {@link Requirement} which evaluates to true iff both requirements, this and
     * other, evaluate to true. If this or other is an {@link AndRequirement} it will be flattened.
     *
     * @param other other requirement to be met.
     * @return a new requirement combining both individual requirements with a logical AND
     *     operation.
     */
    public AndRequirement<R> and(Requirement<R> other) {
        return and(other, true);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff both requirements, this and
     * other, evaluate to true.
     *
     * @param other other requirement to be met.
     * @param flatten If set to false, the requirements will not be flattened.
     * @return a new requirement combining both individual requirements with a logical AND
     *     operation.
     */
    public AndRequirement<R> and(Requirement<R> other, boolean flatten) {
        List<Requirement<R>> requirements = new ArrayList<>();
        if (this instanceof AndRequirement && flatten) {
            requirements.addAll(((AndRequirement<R>) this).getContainedRequirements());
        } else {
            requirements.add(this);
        }
        if (other instanceof AndRequirement && flatten) {
            requirements.addAll(((AndRequirement<R>) other).getContainedRequirements());
        } else {
            requirements.add(other);
        }
        return new AndRequirement<>(requirements);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff at least one of the two
     * requirements is true. If this or other is an {@link OrRequirement} it will be flattened.
     *
     * @param other other requirements to be met.
     * @return a new requirement combining the individual requirements with a logical OR operation.
     */
    public OrRequirement<R> or(Requirement<R> other) {
        return or(other, true);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff at least one of the two
     * requirements is true.
     *
     * @param other other requirements to be met.
     * @param flatten If set to false, the requirements will not be flattened.
     * @return a new requirement combining the individual requirements with a logical OR operation.
     */
    public OrRequirement<R> or(Requirement<R> other, boolean flatten) {
        List<Requirement<R>> requirements = new ArrayList<>();
        if (this instanceof OrRequirement && flatten) {
            requirements.addAll(((OrRequirement<R>) this).getContainedRequirements());
        } else {
            requirements.add(this);
        }
        if (other instanceof OrRequirement && flatten) {
            requirements.addAll(((OrRequirement<R>) other).getContainedRequirements());
        } else {
            requirements.add(other);
        }
        return new OrRequirement<>(requirements);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff this evaluates to false. If
     * this is a {@link NotRequirement}, it will be flattened.
     *
     * @return a new requirement which represents a logical NOT on this requirement.
     */
    public Requirement<R> not() {
        return not(true);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff this evaluates to false.
     *
     * @param flatten If set to false, the requirement will not be flattened.
     * @return a new requirement which represents a logical NOT on this requirement.
     */
    public Requirement<R> not(boolean flatten) {
        if (this instanceof NotRequirement && flatten) {
            return ((NotRequirement<R>) this).getContainedRequirements().get(0);
        }
        return new NotRequirement<>(this);
    }

    /**
     * Creates a new {@link Requirement} which evaluates to true iff either this or other evaluates
     * to true.
     *
     * @param other other requirement to be met.
     * @return a new requirement combining both individual requirements with a logical XOR
     *     operation.
     */
    public XorRequirement<R> xor(Requirement<R> other) {
        return new XorRequirement<>(this, other);
    }

    /**
     * Returns a list of requirements that need to be fulfilled for this requirement to evaluate to
     * true. This will resolve any logical AND operations at the topmost level but may still contain
     * composite requirements (logical OR / NOT).
     *
     * @param report the ScanReport.
     * @return a list of requirements to be met for this requirement to evaluate to true.
     */
    public List<Requirement<R>> getUnfulfilledRequirements(R report) {
        return evaluate(report) ? List.of() : List.of(this);
    }
}
