/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;

/**
 * Abstract class to represent requirements of probes which can be chained to a
 * "chain of Requirements", which can be evaluated for fulfillness, which return
 * their respective "requirement", and which allow to retrieve the not yet
 * fulfilled Requirements.
 */
public abstract class Requirement {

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
	 * @param report the ScanReport.
	 * @return result of the evaluation of this Requirement as Boolean.
	 */
	protected abstract boolean evaluateIntern(ScanReport report);

	/**
	 * Evaluation of "all" Requirement. This and the next ones.
	 *
	 * @param report the ScanReport
	 * @return result of the evaluation of this and the next Requirement as Boolean
	 */
	public boolean evaluate(ScanReport report) {
		return next.evaluate(report) && evaluateIntern(report);
	}

	/**
	 * Adds a Requirement to the Requirement chain. Important: only use this
	 * function once per Requirement. If using both options one Requirement will be
	 * ignored.
	 *
	 * <p>
	 * Either
	 * exampleRequirement.requires(nextRequirement).requires(anotherRequirement) XOR
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
	 * Evaluates if this Requirement and the next are fulfilled or not and adds them
	 * to a Requirement chain of missing Requirements of not fulfilled.
	 *
	 * @param missing reference to the "first" missing Requirement of the missing
	 *                Requirements chain onto which the next missing Requirement is
	 *                attached as next Requirement.
	 * @param report  the ScanReport.
	 * @return a reference to the "first" currently missing Requirement of the
	 *         missing Requirement chain.
	 */
	public abstract Requirement getMissingRequirementIntern(Requirement missing, ScanReport report);

	/**
	 * Rudimentary Requirement which serves as anchor for Requirement chains and the
	 * missing Requirement chains. Evaluates to true and is used as static
	 * NO_REQUIREMENT if a probe can be executed without any requirement.
	 */
	public static class BaseRequirement extends Requirement {
		@Override
		protected boolean evaluateIntern(ScanReport report) {
			return true;
		}

		@Override
		public boolean evaluate(ScanReport report) {
			return true;
		}

		@Override
		public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
			return missing;
		}
	}
}
