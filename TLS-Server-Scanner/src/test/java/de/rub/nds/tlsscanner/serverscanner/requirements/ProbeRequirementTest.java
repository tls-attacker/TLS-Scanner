package de.rub.nds.tlsscanner.serverscanner.requirements;

import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class ProbeRequirementTest {
	private ProbeType probe = ProbeType.ALPN;
	private ProbeType pType = ProbeType.PROTOCOL_VERSION;
	private ExtensionType eType = ExtensionType.TOKEN_BINDING;
	private AnalyzedProperty aProp = AnalyzedProperty.SUPPORTS_DES;
    private SiteReport report;
    
	/**
	 * Set up of testing
	 */
	@Before
	public void setUp() {
		if (this.reqs==null) {
			report = new SiteReport("test host", 0);
		}
	}
	
	/**
	 * Test different instantiations of the probe requirements
	 */
	@Test
	public void createProbeRequirementsTest() {
		ProbeRequirement pReq = new ProbeRequirement(report);
		assertTrue(pReq.getFirst()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()==null && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()==null && pReq.getSecond()==null);
		pReq.requireAnalyzedProperties(aProp);
		assertTrue(pReq.getFirst()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()==null && pReq.getSecond()==null);
		pReq.requireProbeTypes(pType);
		assertTrue(pReq.getFirst()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()[0].equals(pType) && pReq.getSecond()==null);
		pReq.requireExtensionTyes(eType);
		assertTrue(pReq.getFirst()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType) && pReq.getSecond()==null);
		ProbeRequirement pReq1 = new ProbeRequirement(report);
		ProbeRequirement pReq2 = new ProbeRequirement(report);
		pReq.orRequirement(pReq1, pReq2);
		assertTrue(pReq.getFirst().equals(pReq1) && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType) && pReq.getSecond().equals(pReq2));
		pReq1.notRequirement(pReq2);
		assertTrue(pReq1.getFirst()==null && pReq1.getNot().equals(pReq2) && pReq1.getRequiredAnalyzedproperties()==null && pReq1.getRequiredExtensionTypes()==null && pReq1.getRequiredProbeTypes()==null && pReq1.getSecond()==null);
}

	/**
	 * Test evaluation of the probe requirements
	 */
	@Test
	public void evaluateProbeRequirementsTest() {
		
	}
}
