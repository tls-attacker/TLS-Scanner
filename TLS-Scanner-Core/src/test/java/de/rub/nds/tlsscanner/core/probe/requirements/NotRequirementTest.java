/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class NotRequirementTest {

	@Test
	public void testNotRequirement() {
		TestReport report = new TestReport();
		ProbeRequirement requirementNot = new ProbeRequirement(TlsProbeType.BASIC);

		NotRequirement requirement = new NotRequirement(null);
		assertTrue(requirement.evaluate(report));

		requirement = new NotRequirement(requirementNot);
		assertEquals(requirement.getRequirement(), requirementNot);
		assertTrue(requirement.evaluate(report));
		report.markProbeAsExecuted(TlsProbeType.BASIC);
		assertFalse(requirement.evaluate(report));

		Requirement reqMis = requirement.getMissingRequirements(report);
		assertFalse(requirement.evaluate(report));
		assertEquals(((NotRequirement) reqMis).getRequirement(), requirement.getRequirement());
	}
}
