/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class RequirementsBasicTest {

    private TestReport report;

    @BeforeEach
    public void setup() {
        report = new TestReport();
    }

    @Test
    public void requirementsTest() {
        Requirement requirements =
                new ExtensionRequirement(new ExtensionType[] {ExtensionType.ALPN});
        assertFalse(requirements.evaluate(report));
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                new ListResult<>(
                        Arrays.asList(new ExtensionType[] {ExtensionType.ALPN}),
                        TlsAnalyzedProperty.SUPPORTED_EXTENSIONS.name()));
        assertTrue(requirements.evaluate(report));

        TlsProbeType probe = TlsProbeType.ALPN;
        ScannerProbe<TestReport> alpnProbe = new TestProbeAlpn<TestReport>(null);
        requirements = requirements.requires(new ProbeRequirement(probe));
        assertFalse(requirements.evaluate(report));
        report.markProbeAsExecuted(alpnProbe.getType());
        assertTrue(requirements.evaluate(report));

        TlsAnalyzedProperty[] propertyNot =
                new TlsAnalyzedProperty[] {TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES};
        requirements = requirements.requires(new PropertyNotRequirement(propertyNot));
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.TRUE);
        assertFalse(requirements.evaluate(report));
        report.putResult(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, TestResults.FALSE);
        assertTrue(requirements.evaluate(report));

        TlsAnalyzedProperty[] property =
                new TlsAnalyzedProperty[] {
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE
                };
        requirements = requirements.requires(new PropertyRequirement(property));
        assertFalse(requirements.evaluate(report));
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.FALSE);
        assertFalse(requirements.evaluate(report));
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, TestResults.TRUE);
        assertTrue(requirements.evaluate(report));

        ProtocolVersion[] prot = new ProtocolVersion[] {ProtocolVersion.TLS10};
        requirements = requirements.requires(new ProtocolRequirement(prot));
        assertFalse(requirements.evaluate(report));
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                new ListResult<>(
                        Arrays.asList(prot),
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS.name()));
        assertTrue(requirements.evaluate(report));

        ProbeRequirement requirement0 = new ProbeRequirement(TlsProbeType.BLEICHENBACHER);
        ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);
        requirements = requirements.requires(new OrRequirement(requirement0, requirement1));
        assertFalse(requirements.evaluate(report));
        ScannerProbe<TestReport> basicProbe = new TestProbeBasic<TestReport>(null);
        report.markProbeAsExecuted(basicProbe.getType());
        assertTrue(requirements.evaluate(report));

        ProbeRequirement requirementNot = new ProbeRequirement(TlsProbeType.CCA);
        requirements = requirements.requires(new NotRequirement(requirementNot));
        assertTrue(requirements.evaluate(report));
        ScannerProbe<TestReport> ccaProbe = new TestProbeCca<TestReport>(null);
        report.markProbeAsExecuted(ccaProbe.getType());
        assertFalse(requirements.evaluate(report));

        assertEquals(
                requirements.name(),
                "(not CCA) and (BLEICHENBACHER or BASIC) and TLS10 and ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE and (not ACCEPTS_RANDOM_MESSAGE_SEQUENCES) and ALPN and ALPN");

        assertArrayEquals(
                requirements.getRequirements(),
                new Enum<?>[] {
                    TlsProbeType.CCA,
                    TlsProbeType.BLEICHENBACHER,
                    TlsProbeType.BASIC,
                    ProtocolVersion.TLS10,
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                    TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES,
                    TlsProbeType.ALPN,
                    ExtensionType.ALPN
                });
    }

    @Test
    public void missingTest() {
        ProbeRequirement requirement1 = new ProbeRequirement(TlsProbeType.BASIC);
        Requirement requirement =
                new ProbeRequirement(TlsProbeType.BLEICHENBACHER).requires(requirement1);
        Set<Enum<?>> set1 = new HashSet<>(), set2 = new HashSet<>();
        set1.add(((ProbeRequirement) requirement).getRequirement()[0]);
        set1.add(((ProbeRequirement) requirement.getNext()).getRequirement()[0]);

        set2.add(
                ((ProbeRequirement) requirement.getMissingRequirements(report))
                        .getRequirement()[0]);
        set2.add(
                ((ProbeRequirement) requirement.getMissingRequirements(report).getNext())
                        .getRequirement()[0]);
        assertEquals(set1, set2);
    }
}
