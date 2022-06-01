package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.Test;

public class ProtocolRequirementTest extends RequirementsBasicTest{
	@Test
	public void testProtocolRequirement() {
		TestReport report = new TestReport();
		ProtocolVersion[] prot = new ProtocolVersion[]{ProtocolVersion.TLS10};
		
		ProtocolRequirement req = new ProtocolRequirement(null);
		assertTrue(req.evaluate(report));
		
		req = new ProtocolRequirement(new ProtocolVersion[0]);
		assertTrue(req.evaluate(report));
				
		req =new ProtocolRequirement(prot);
		assertArrayEquals(req.getRequirement(), prot);
		assertFalse(req.evaluate(report));
		report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS, new ListResult<>(Arrays.asList(prot), "LIST_SUPPORTED_PROTOCOLVERSIONS"));
		assertTrue(req.evaluate(report));
	}
}
