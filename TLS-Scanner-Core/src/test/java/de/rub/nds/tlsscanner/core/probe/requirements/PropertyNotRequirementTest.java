package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.Test;

public class PropertyNotRequirementTest extends RequirementsBasicTest{

	@Test
	public void testPropertyNotRequirement() {
		TestReport report = new TestReport();
		TlsAnalyzedProperty[] propNot = new TlsAnalyzedProperty[]{TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES};
		
		PropertyNotRequirement req = new PropertyNotRequirement(null);
		assertTrue(req.evaluate(report));
		
		req = new PropertyNotRequirement(new TlsAnalyzedProperty[0]);
		assertTrue(req.evaluate(report));
				
		req =new PropertyNotRequirement(propNot);
		assertArrayEquals(req.getRequirement(), propNot);
		assertFalse(req.evaluate(report));
		report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
		assertFalse(req.evaluate(report));
		report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
		assertTrue(req.evaluate(report));
	}
}
