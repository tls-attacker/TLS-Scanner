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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class ProbeRequirementTest {
	@Test
	public void testProbeRequirement() {
		TestReport report = new TestReport();
		TlsProbeType probe = TlsProbeType.ALPN;

		ProbeRequirement requirement = new ProbeRequirement();
		assertTrue(requirement.evaluate(report));

		requirement = new ProbeRequirement(new TlsProbeType[0]);
		assertTrue(requirement.evaluate(report));

		requirement = new ProbeRequirement(probe);
		assertArrayEquals(requirement.getRequirement(), new TlsProbeType[] { probe });
		assertFalse(requirement.evaluate(report));

		Requirement requirementMissing = requirement.getMissingRequirements(report);
		assertFalse(requirement.evaluate(report));
		assertArrayEquals(((ProbeRequirement) requirementMissing).getRequirement(), requirement.getRequirement());

		report.markProbeAsExecuted(probe);
		assertTrue(requirement.evaluate(report));
		assertTrue(requirementMissing.evaluate(report));
	}

}