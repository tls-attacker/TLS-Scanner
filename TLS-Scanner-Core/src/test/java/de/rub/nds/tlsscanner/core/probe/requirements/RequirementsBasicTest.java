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
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;

public class RequirementsBasicTest {

    /**
     * Implementation of ScanReport
     */
    public class TestReport extends ScanReport {
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
        Requirement reqs = new ExtensionRequirement(new ExtensionType[] { ExtensionType.ALPN });
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS,
            new ListResult<>(Arrays.asList(new ExtensionType[] { ExtensionType.ALPN }), "LIST_SUPPORTED_EXTENSIONS"));
        assertTrue(reqs.evaluate(report));

        TlsProbeType probe = TlsProbeType.ALPN;
        reqs = reqs.requires(new ProbeRequirement(probe));
        assertFalse(reqs.evaluate(report));
        report.markProbeAsExecuted(probe);
        assertTrue(reqs.evaluate(report));

        TlsAnalyzedProperty[] propNot =
            new TlsAnalyzedProperty[] { TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES };
        reqs = reqs.requires(new PropertyNotRequirement(propNot));
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
        assertTrue(reqs.evaluate(report));

        TlsAnalyzedProperty[] prop =
            new TlsAnalyzedProperty[] { TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE };
        reqs = reqs.requires(new PropertyRequirement(prop));
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.FALSE);
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.TRUE);
        assertTrue(reqs.evaluate(report));

        ProtocolVersion[] prot = new ProtocolVersion[] { ProtocolVersion.TLS10 };
        reqs = reqs.requires(new ProtocolRequirement(prot));
        assertFalse(reqs.evaluate(report));
        report.putResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS,
            new ListResult<>(Arrays.asList(prot), "LIST_SUPPORTED_PROTOCOLVERSIONS"));
        assertTrue(reqs.evaluate(report));

        ProbeRequirement req0 = new ProbeRequirement(TlsProbeType.BLEICHENBACHER);
        ProbeRequirement req1 = new ProbeRequirement(TlsProbeType.BASIC);
        reqs = reqs.requires(new OrRequirement(req0, req1));
        assertFalse(reqs.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.BASIC);
        assertTrue(reqs.evaluate(report));

        ProbeRequirement reqNot = new ProbeRequirement(TlsProbeType.CCA);
        reqs = reqs.requires(new NotRequirement(reqNot));
        assertTrue(reqs.evaluate(report));
        report.markProbeAsExecuted(TlsProbeType.CCA);
        assertFalse(reqs.evaluate(report));
    }

    @Test
    public void missingTest() {
        ProbeRequirement req1 = new ProbeRequirement(TlsProbeType.BASIC);
        Requirement req = new ProbeRequirement(TlsProbeType.BLEICHENBACHER).requires(req1);
        Set<TlsProbeType> set1 = new HashSet<>(), set2 = new HashSet<>();
        set1.add(((ProbeRequirement) req).getRequirement()[0]);
        set1.add(((ProbeRequirement) req.getNext()).getRequirement()[0]);

        set2.add(((ProbeRequirement) req.getMissingRequirements(report)).getRequirement()[0]);
        set2.add(((ProbeRequirement) req.getMissingRequirements(report).getNext()).getRequirement()[0]);
        assertEquals(set1, set2);
    }
}
