/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;

/**
 * Represents a {@link Requirement} for required negated Requirements. If the
 * contained Requirement evaluates to true, this Requirement evaluates to false
 * and vice versa.
 */
public class NotRequirement extends Requirement {
	private final Requirement notRequirement;

	/**
	 * @param notRequirement the Requirement to negate.
	 */
	public NotRequirement(Requirement notRequirement) {
		super();
		this.notRequirement = notRequirement;
	}

	@Override
	protected boolean evaluateIntern(ScanReport report) {
		if (notRequirement == null) {
			return true;
		}
		return !notRequirement.evaluate(report);
	}

	/**
	 * @return the Requirement to negate.
	 */
	public Requirement getRequirement() {
		return notRequirement;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		if (evaluateIntern(report) == false) {
			return next.getMissingRequirementIntern(missing.requires(new NotRequirement(notRequirement)), report);
		}
		return next.getMissingRequirementIntern(missing, report);
	}
}
