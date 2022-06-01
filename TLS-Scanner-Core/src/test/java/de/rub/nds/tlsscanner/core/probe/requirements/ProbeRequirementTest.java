/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

public class ProbeRequirementTest {
    private TlsProbeType pType = TlsProbeType.PROTOCOL_VERSION;
    private ExtensionType eType = ExtensionType.TOKEN_BINDING;
    private TlsAnalyzedProperty aProp = TlsAnalyzedProperty.SUPPORTS_DES;
    private ProtocolVersion pVer = ProtocolVersion.DTLS10;
    private ScanReport report;

    /**
     * Implementation of ScanReport
     */
    private class TestReport extends ScanReport {

        private static final long serialVersionUID = 1L;

        public TestReport() {
            super();
        }

        @Override
        public String getFullReport(ScannerDetail detail, boolean printColorful) {
            return null;
        }
    }

    /**
     * Set up of testing
     */
    @Before
    public void setUp() {
        if (this.report == null)
            this.report = new TestReport();
    }

    /**
     * Test different instantiations of the probe requirements
     */
    @Test
    public void createProbeRequirementsTest() {
        ProbeRequirement pReq = new ProbeRequirement();
        assertTrue(
            pReq.getORRequirements() == null && pReq.getNot() == null && pReq.getRequiredAnalyzedproperties() == null
                && pReq.getRequiredExtensionTypes() == null && pReq.getRequiredProbeTypes() == null);

        pReq.requireAnalyzedPropertiesNot(aProp);
        assertTrue(pReq.getRequiredAnalyzedpropertiesNot()[0].equals(aProp));

        pReq.requireAnalyzedProperties(aProp);
        assertTrue(pReq.getORRequirements() == null && pReq.getNot() == null
            && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes() == null
            && pReq.getRequiredProbeTypes() == null);

        pReq.requireProbeTypes(pType);
        assertTrue(pReq.getORRequirements() == null && pReq.getNot() == null
            && pReq.getRequiredAnalyzedproperties()[0].equals(aProp) && pReq.getRequiredExtensionTypes() == null
            && pReq.getRequiredProbeTypes()[0].equals(pType));

        pReq.requireExtensionTyes(eType);
        assertTrue(pReq.getORRequirements() == null && pReq.getNot() == null
            && pReq.getRequiredAnalyzedproperties()[0].equals(aProp)
            && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType));

        ProbeRequirement pReq1 = new ProbeRequirement();
        ProbeRequirement pReq2 = new ProbeRequirement();
        pReq.orRequirement(pReq1, pReq2);
        assertTrue((pReq.getORRequirements()[0].equals(pReq1) && pReq.getORRequirements()[1].equals(pReq2)
            || pReq.getORRequirements()[1].equals(pReq1) && pReq.getORRequirements()[0].equals(pReq2))
            && pReq.getNot() == null && pReq.getRequiredAnalyzedproperties()[0].equals(aProp)
            && pReq.getRequiredExtensionTypes()[0].equals(eType) && pReq.getRequiredProbeTypes()[0].equals(pType));

        pReq1.notRequirement(pReq2);
        assertTrue(pReq1.getORRequirements() == null && pReq1.getNot().equals(pReq2)
            && pReq1.getRequiredAnalyzedproperties() == null && pReq1.getRequiredExtensionTypes() == null
            && pReq1.getRequiredProbeTypes() == null);

        assertTrue(pReq.getRequiredProtocolVersions() == null);
        pReq.requireProtocolVersions(pVer);
        assertTrue(pReq.getRequiredProtocolVersions()[0].equals(pVer));
    }

    /**
     * Test evaluation of the probe requirements
     */
    @Test
    public void evaluateProbeRequirementsTest() {
        ProbeRequirement pReq = new ProbeRequirement();
        assertTrue(pReq.evaluate(report) == true);

        ProbeRequirement pReq1 = new ProbeRequirement();
        ProbeRequirement pReq2 = new ProbeRequirement();

        ProbeRequirement pReqNot = new ProbeRequirement().requireAnalyzedPropertiesNot(aProp);
        report.putResult(aProp, TestResults.FALSE);
        assertTrue(pReqNot.evaluate(report));

        pReq2.notRequirement(pReq1);
        assertFalse(pReq2.evaluate(report));

        pReq.orRequirement(pReq1, pReq2);
        assertTrue(pReq.evaluate(report));

        pReq1.requireAnalyzedProperties(aProp);
        assertTrue(pReq.evaluate(report));
        assertTrue(pReq2.evaluate(report));

        pReq2.requireAnalyzedProperties(aProp);
        assertFalse(pReq.evaluate(report));

        pReq.requireAnalyzedProperties(aProp);
        assertFalse(pReq.evaluate(report));
        report.putResult(aProp, TestResults.TRUE);
        assertTrue(pReq.evaluate(report));
        assertFalse(pReqNot.evaluate(report));

        pReq.requireProbeTypes(pType);
        assertFalse(pReq.evaluate(report));
        report.markProbeAsExecuted(pType);
        assertTrue(pReq.evaluate(report));

        pReq.requireProtocolVersions(pVer);
        assertFalse(pReq.evaluate(report));
        List<ProtocolVersion> pList = new ArrayList<ProtocolVersion>();
        pList.add(pVer);
        report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS,
            new ListResult<>(pList, TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS.name()));
        assertTrue(pReq.evaluate(report));

        pReq.requireExtensionTyes(eType);
        assertFalse(pReq.evaluate(report));
        assertTrue(pReq.getMissingRequirements(report).getRequiredExtensionTypes()[0] == eType);
        List<ExtensionType> etList = new ArrayList<ExtensionType>();
        etList.add(eType);
        report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS,
            new ListResult<>(etList, TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS.name()));
        assertTrue(pReq.evaluate(report));

        assertTrue(ProbeRequirement.NO_REQUIREMENT.evaluate(report));
    }
}