package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import org.junit.Test;

public class OrRequirementTest extends RequirementsBasicTest {

	@Test
	public void testOrRequirement() {
		TestReport report = new TestReport();
		
		ProbeRequirement req0 = new ProbeRequirement(TlsProbeType.ALPN);
		ProbeRequirement req1 = new ProbeRequirement(TlsProbeType.BASIC);
		
		
		OrRequirement req = new OrRequirement(Requirement.NO_REQUIREMENT, null);
		assertTrue(req.evaluate(report));
		
		req = new OrRequirement(new Requirement[0]);
		assertTrue(req.evaluate(report));
				
		req = new OrRequirement(req0, req1);
		assertArrayEquals(req.getRequirement(), new Requirement[] {req0, req1});
		assertFalse(req.evaluate(report));
		report.markProbeAsExecuted(TlsProbeType.BASIC);
		assertTrue(req.evaluate(report));
	}
}
