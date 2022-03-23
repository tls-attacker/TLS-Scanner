package de.rub.nds.tlsscanner.serverscanner.requirements;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

public class ProbeRequirementTest {
	private ProbeType pType = ProbeType.PROTOCOL_VERSION;
	private ExtensionType eType = ExtensionType.TOKEN_BINDING;
	private AnalyzedProperty aProp = AnalyzedProperty.SUPPORTS_DES;
    private SiteReport report;
    
	/**
	 * Set up of testing
	 */
	@Before
	public void setUp() {
		if (this.report==null) {
			report = new SiteReport("test host", 0);
		}
	}
	
	/**
	 * Test different instantiations of the probe requirements
	 */
	@Test
	public void createProbeRequirementsTest() {
		ProbeRequirement pReq = new ProbeRequirement(report);
		assertTrue(pReq.getORRequirements()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()==null && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()==null);
		
		pReq.requireAnalyzedProperties(aProp);
		assertTrue(pReq.getORRequirements()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()==null);
		
		pReq.requireProbeTypes(pType);
		assertTrue(pReq.getORRequirements()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()==null && pReq.getRequiredProbeTypes()[0].equals(pType));
		
		pReq.requireExtensionTyes(eType);
		assertTrue(pReq.getORRequirements()==null && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType));
		
		ProbeRequirement pReq1 = new ProbeRequirement(report);
		ProbeRequirement pReq2 = new ProbeRequirement(report);
		pReq.orRequirement(pReq1, pReq2);
		assertTrue((pReq.getORRequirements()[0].equals(pReq1) && pReq.getORRequirements()[1].equals(pReq2) || pReq.getORRequirements()[1].equals(pReq1) && pReq.getORRequirements()[0].equals(pReq2)) && pReq.getNot()==null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType));
		
		pReq1.notRequirement(pReq2);
		assertTrue(pReq1.getORRequirements()==null && pReq1.getNot().equals(pReq2) && pReq1.getRequiredAnalyzedproperties()==null && pReq1.getRequiredExtensionTypes()==null && pReq1.getRequiredProbeTypes()==null);
}

	/**
	 * Test evaluation of the probe requirements
	 */
	@Test
	public void evaluateProbeRequirementsTest() {
		ProbeRequirement pReq = new ProbeRequirement(report);
		assertTrue(pReq.evaluateRequirements()==true);
		
		ProbeRequirement pReq1 = new ProbeRequirement(report);
		ProbeRequirement pReq2 = new ProbeRequirement(report);
		
		pReq2.notRequirement(pReq1);
		assertFalse(pReq2.evaluateRequirements()==true);
		
		pReq.orRequirement(pReq1, pReq2);
		assertTrue(pReq.evaluateRequirements()==true);
		
		pReq1.requireAnalyzedProperties(aProp);
		assertTrue(pReq.evaluateRequirements()==true);
		assertTrue(pReq2.evaluateRequirements()==true);
		
		pReq2.requireAnalyzedProperties(aProp);
		assertFalse(pReq.evaluateRequirements()==true);

		pReq.requireAnalyzedProperties(aProp);
		assertFalse(pReq.evaluateRequirements()==true);
		report.putResult(aProp, TestResults.TRUE);
		assertTrue(pReq.evaluateRequirements()==true);
		
		pReq.requireProbeTypes(pType);
		assertFalse(pReq.evaluateRequirements()==true);
		report.markProbeAsExecuted(pType);
		assertTrue(pReq.evaluateRequirements()==true);
		
		pReq.requireExtensionTyes(eType);
		assertFalse(pReq.evaluateRequirements()==true);
		List<ExtensionType> etList = new ArrayList<ExtensionType>();
		etList.add(eType);
		report.setSupportedExtensions(etList);
		for (ExtensionType et : report.getSupportedExtensions()) {
			System.out.println(et);
		}
		assertTrue(pReq.evaluateRequirements()==true);
	}
}
