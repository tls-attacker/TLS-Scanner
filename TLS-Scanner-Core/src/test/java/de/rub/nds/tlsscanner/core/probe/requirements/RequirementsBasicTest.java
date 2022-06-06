/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsReport;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;

public class RequirementsBasicTest {

    /**
     * Implementation of ScanReport
     */
    public class TestReport extends TlsReport {
        private static final long serialVersionUID = 1L;

        public TestReport() {
            super();
        }

        @Override
        public String getFullReport(ScannerDetail detail, boolean printColorful) {
            return null;
        }
    }

    private TestReport report;

    @Before
    public void setup() {
        report = new TestReport();
    }

    @Test
    public void requirementsTest() {
        Requirement requirements = new ExtensionRequirement(new ExtensionType[] { ExtensionType.ALPN });
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
            new ListResult<>(Arrays.asList(new ExtensionType[] { ExtensionType.ALPN }), "SUPPORTED_EXTENSIONS"));
        assertTrue(requirements.evaluate(report));

        TlsProbeType probe = TlsProbeType.ALPN;
        requirements = requirements.requires(new ProbeRequirement(probe));
        assertFalse(requirements.evaluate(report));
        report.markProbeAsExecuted(probe);
        assertTrue(requirements.evaluate(report));

        TlsAnalyzedProperty[] propertyNot =
            new TlsAnalyzedProperty[] { TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES };
        requirements = requirements.requires(new PropertyNotRequirement(propertyNot));
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
        assertTrue(requirements.evaluate(report));

        TlsAnalyzedProperty[] property =
            new TlsAnalyzedProperty[] { TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE };
        requirements = requirements.requires(new PropertyRequirement(property));
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.FALSE);
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.TRUE);
        assertTrue(requirements.evaluate(report));

        ProtocolVersion[] prot = new ProtocolVersion[] { ProtocolVersion.TLS10 };
        requirements = requirements.requires(new ProtocolRequirement(prot));
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOLVERSIONS,
            new ListResult<>(Arrays.asList(prot), "SUPPORTED_PROTOCOLVERSIONS"));
        assertTrue(requirements.evaluate(report));

        ProbeRequirement requirement0 = new ProbeRequirement(TlsProbeType.BLEICHENBACHER);
        ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);
        requirements = requirements.requires(new OrRequirement(requirement0, requirement1));
        assertFalse(requirements.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertTrue(requirements.evaluate(report));

        ProbeRequirement requirementNot = new ProbeRequirement(TlsProbeType.CCA);
        requirements = requirements.requires(new NotRequirement(requirementNot));
        assertTrue(requirements.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.CCA);
        assertFalse(requirements.evaluate(report));
    }

    @Test
    public void missingTest() {
        ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);
        Requirement requirement = new ProbeRequirement(TlsProbeType.BLEICHENBACHER).requires(requirement1);
        Set<TlsProbeType> set1 = new HashSet<>(), set2 = new HashSet<>();
        set1.add(((ProbeRequirement) requirement).getRequirement()[0]);
        set1.add(((ProbeRequirement) requirement.getNext()).getRequirement()[0]);

        set2.add(((ProbeRequirement) requirement.getMissingRequirements(report)).getRequirement()[0]);
        set2.add(((ProbeRequirement) requirement.getMissingRequirements(report).getNext()).getRequirement()[0]);
        assertEquals(set1, set2);
    }
}
