/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class OrRequirementTest {

	@Test
	public void testOrRequirement() {
		TestReport report = new TestReport();

		ProbeRequirement requirement0 = new ProbeRequirement(TlsProbeType.ALPN);
		ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);

		OrRequirement requirement = new OrRequirement();
		assertTrue(requirement.evaluate(report));

		requirement = new OrRequirement(new Requirement[0]);
		assertTrue(requirement.evaluate(report));

		requirement = new OrRequirement(requirement0, requirement1);
		assertArrayEquals(requirement.getRequirement(), new Requirement[] { requirement0, requirement1 });
		assertFalse(requirement.evaluate(report));

		Requirement requirementMissing = requirement.getMissingRequirements(report);
		assertFalse(requirement.evaluate(report));
		assertArrayEquals(((OrRequirement) requirementMissing).getRequirement(), requirement.getRequirement());

		report.markProbeAsExecuted(TlsProbeType.BASIC);
		assertTrue(requirement.evaluate(report));

		requirementMissing = requirement.getMissingRequirements(report);
		assertEquals(requirementMissing, Requirement.NO_REQUIREMENT);
	}
}
