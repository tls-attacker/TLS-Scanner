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

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.Test;

public class PropertyRequirementTest {

	@Test
	public void testPropertyRequirement() {
		TestReport report = new TestReport();
		TlsAnalyzedProperty[] property = new TlsAnalyzedProperty[] {
				TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES };

		PropertyRequirement requirement = new PropertyRequirement();
		assertTrue(requirement.evaluate(report));

		requirement = new PropertyRequirement(new TlsAnalyzedProperty[0]);
		assertTrue(requirement.evaluate(report));

		requirement = new PropertyRequirement(property);
		assertArrayEquals(requirement.getRequirement(), property);
		assertFalse(requirement.evaluate(report));

		Requirement reqMis = requirement.getMissingRequirements(report);
		assertFalse(requirement.evaluate(report));
		assertArrayEquals(((PropertyRequirement) reqMis).getRequirement(), requirement.getRequirement());

		report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
		assertFalse(requirement.evaluate(report));
		report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
		assertTrue(requirement.evaluate(report));
	}
}
