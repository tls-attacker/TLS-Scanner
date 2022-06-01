package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class NotRequirementTest extends RequirementsBasicTest{

	@Test
	public void testNotRequirement() {
		TestReport report = new TestReport();
		ProbeRequirement reqNot = new ProbeRequirement(TlsProbeType.BASIC);
		
		NotRequirement req = new NotRequirement(null);
		assertTrue(req.evaluate(report));
		
		req = new NotRequirement(reqNot);
		assertEquals(req.getRequirement(), reqNot);
		assertTrue(req.evaluate(report));
		report.markProbeAsExecuted(TlsProbeType.BASIC);
		assertFalse(req.evaluate(report));
	}
}
