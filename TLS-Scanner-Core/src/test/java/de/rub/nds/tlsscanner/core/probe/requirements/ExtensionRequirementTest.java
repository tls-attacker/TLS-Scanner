package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import org.junit.Test;

public class ExtensionRequirementTest extends RequirementsBasicTest{

	@Test
	public void testExtensionRequirement() {
		TestReport report = new TestReport();
		ExtensionType[] ext = new ExtensionType[]{ExtensionType.ALPN};
		
		ExtensionRequirement req = new ExtensionRequirement(null);
		assertTrue(req.evaluate(report));
		
		req = new ExtensionRequirement(new ExtensionType[0]);
		assertTrue(req.evaluate(report));
				
		req =new ExtensionRequirement(ext);
		assertArrayEquals(req.getRequirement(), ext);
		assertFalse(req.evaluate(report));
		report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS, new ListResult<>(Arrays.asList(ext), "LIST_SUPPORTED_EXTENSIONS"));
		assertTrue(req.evaluate(report));
	}
}
