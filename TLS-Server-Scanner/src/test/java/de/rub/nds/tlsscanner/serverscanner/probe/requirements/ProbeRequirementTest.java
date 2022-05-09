/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

public class ProbeRequirementTest {
    private TlsProbeType pType = TlsProbeType.PROTOCOL_VERSION;
    private ExtensionType eType = ExtensionType.TOKEN_BINDING;
    private TlsAnalyzedProperty aProp = TlsAnalyzedProperty.SUPPORTS_DES;
    private ProtocolVersion pVer = ProtocolVersion.DTLS10;
    private ServerReport report;

    /**
     * Set up of testing
     */
    @Before
    public void setUp() {
        if (this.report == null)
            this.report = new ServerReport("test host", 0);
    }

    /**
     * Test different instantiations of the probe requirements
     */
    @Test
    public void createProbeRequirementsTest() {
        ProbeRequirement pReq = new ProbeRequirement(report);
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

        ProbeRequirement pReq1 = new ProbeRequirement(report);
        ProbeRequirement pReq2 = new ProbeRequirement(report);
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
        ProbeRequirement pReq = new ProbeRequirement(report);
        assertTrue(pReq.evaluateRequirements() == true);

        ProbeRequirement pReq1 = new ProbeRequirement(report);
        ProbeRequirement pReq2 = new ProbeRequirement(report);

        ProbeRequirement pReqNot = new ProbeRequirement(report).requireAnalyzedPropertiesNot(aProp);
        report.putResult(aProp, TestResults.FALSE);
        assertTrue(pReqNot.evaluateRequirements());

        pReq2.notRequirement(pReq1);
        assertFalse(pReq2.evaluateRequirements());

        pReq.orRequirement(pReq1, pReq2);
        assertTrue(pReq.evaluateRequirements());

        pReq1.requireAnalyzedProperties(aProp);
        assertTrue(pReq.evaluateRequirements());
        assertTrue(pReq2.evaluateRequirements());

        pReq2.requireAnalyzedProperties(aProp);
        assertFalse(pReq.evaluateRequirements());

        pReq.requireAnalyzedProperties(aProp);
        assertFalse(pReq.evaluateRequirements());
        report.putResult(aProp, TestResults.TRUE);
        assertTrue(pReq.evaluateRequirements());
        assertFalse(pReqNot.evaluateRequirements());

        pReq.requireProbeTypes(pType);
        assertFalse(pReq.evaluateRequirements());
        report.markProbeAsExecuted(pType);
        assertTrue(pReq.evaluateRequirements());

        pReq.requireProtocolVersions(pVer);
        assertFalse(pReq.evaluateRequirements());
        List<ProtocolVersion> pList = new ArrayList<ProtocolVersion>();
        pList.add(pVer);
        report.setVersions(pList);
        ;
        assertTrue(pReq.evaluateRequirements());

        pReq.requireExtensionTyes(eType);
        assertFalse(pReq.evaluateRequirements());
        assertTrue(pReq.getMissingRequirements().getRequiredExtensionTypes()[0] == eType);
        List<ExtensionType> etList = new ArrayList<ExtensionType>();
        etList.add(eType);
        report.setSupportedExtensions(etList);
        assertTrue(pReq.evaluateRequirements());
        
        assertTrue(ProbeRequirement.NO_REQUIREMENT.evaluateRequirements());
    }
}
