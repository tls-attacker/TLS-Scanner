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
import java.util.Arrays;
import java.util.List;

/**
 * Abstract class to represent requirements of probes which can be chained to a "chain of
 * Requirements", which can be evaluated for fulfillness, which return their respective
 * "requirement", and which allow to retrieve the not yet fulfilled Requirements.
 */
public abstract class Requirement {
    protected enum SpecialRequirementTypes {
        OPTIONS_ALPN,
        OPTIONS_RESUMPTION,
        OPTIONS_SNI,
        WORKING_CONFIG
    }

    /*
     * Holds the "next" Requirement. Holds the NO_REQUIREMENT by default if no
     * Requirement is set as next.
     */
    protected Requirement next = Requirement.NO_REQUIREMENT;

    /* no requirement, always evaluates to true */
    public static BaseRequirement NO_REQUIREMENT = new BaseRequirement();

    /**
     * Evaluation of "this" Requirement itself.
     *
     * @param report the {@link ScanReport}.
     * @return result of the evaluation of this Requirement as Boolean.
     */
    protected abstract boolean evaluateInternal(ScanReport report);

    /**
     * Evaluation of "all" Requirement. This and the next ones.
     *
     * @param report the {@link ScanReport}
     * @return result of the evaluation of this and the next Requirement as Boolean
     */
    public boolean evaluate(ScanReport report) {
        return next.evaluate(report) && evaluateInternal(report);
    }

    /**
     * Adds a Requirement to the Requirement chain. Important: only use this function once per
     * Requirement. If using both options one Requirement will be ignored.
     *
     * <p>Either exampleRequirement.requires(nextRequirement).requires(anotherRequirement) XOR
     * exampleRequirement.requires(nextRequirement.requires(anotherRequirement)).
     *
     * @param next the requirement object to add.
     * @return reference to the next requirement.
     */
    public Requirement requires(Requirement next) {
        next.next = this;
        return next;
    }

    /**
     * Add this Requirement to a chain of not positively evaluated requirements.
     *
     * @param report the ScanReport.
     * @return this and the next Requirement if they evaluate to false respectively.
     */
    public Requirement getMissingRequirements(ScanReport report) {
        Requirement missing = NO_REQUIREMENT;
        return getMissingRequirementIntern(missing, report);
    }

    /**
     * @return the next Requirement.
     */
    public Requirement getNext() {
        return next;
    }

    /**
     * @return returns String representation of the requirement.
     */
    public String name() {
        if (!next.equals(NO_REQUIREMENT)) {
            return toString() + " and " + next.name();
        } else {
            return toString();
        }
    }

    /**
     * @return returns the required parameters of the respective requirement.
     */
    public abstract Enum<?>[] getRequirement();

    /**
     * @return returns the complete requirements as boolean expression.
     */
    public Enum<?>[] getRequirements() {
        if (next.equals(NO_REQUIREMENT)) {
            return getRequirement();
        } else {
            List<Enum<?>> parameters = new ArrayList<>();
            parameters.addAll(Arrays.asList(getRequirement()));
            parameters.addAll(Arrays.asList(next.getRequirements()));
            return parameters.toArray(new Enum<?>[0]);
        }
    }

    /**
     * Evaluates if this Requirement and the next are fulfilled or not and adds them to a
     * Requirement chain of missing Requirements of not fulfilled.
     *
     * @param missing reference to the "first" missing Requirement of the missing Requirements chain
     *     onto which the next missing Requirement is attached as next Requirement.
     * @param report the ScanReport.
     * @return a reference to the "first" currently missing Requirement of the missing Requirement
     *     chain.
     */
    public abstract Requirement getMissingRequirementIntern(Requirement missing, ScanReport report);
}
