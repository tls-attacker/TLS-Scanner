/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DestinationPortAfterProbeTest {

    public final int INITIAL_PORT = 443;
    public final int[] ALTERNATIVE_PORTS = {25, 80, 636, 989, 8443};

    private ServerReport report;
    private DestinationPortAfterProbe probe;
    private ExtractedValueContainer<Integer> destinationPortsContainer;

    @BeforeEach
    public void setup() {
        report = new ServerReport("DestinationPortAfterProbeTest", INITIAL_PORT);
        probe = new DestinationPortAfterProbe();
        destinationPortsContainer =
                new ExtractedValueContainer<>(TrackableValueType.DESTINATION_PORT);
        report.putExtractedValueContainer(
                TrackableValueType.DESTINATION_PORT, destinationPortsContainer);
    }

    @Test
    public void testNoPorts() {
        probe.analyze(report);

        assertEquals(
                TestResults.COULD_NOT_TEST, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));
    }

    @Test
    public void testNoPortChanges() {
        destinationPortsContainer.put(INITIAL_PORT);
        probe.analyze(report);

        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));

        destinationPortsContainer.put(INITIAL_PORT);
        probe.analyze(report);

        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));
    }

    @Test
    public void testSinglePortChange() {
        destinationPortsContainer.put(ALTERNATIVE_PORTS[0]);
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));

        destinationPortsContainer.put(ALTERNATIVE_PORTS[0]);
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));
    }

    @Test
    public void testMultipleDistinctPortChanges() {
        for (int port : ALTERNATIVE_PORTS) {
            destinationPortsContainer.put(port);
        }
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));
    }

    @Test
    public void testMultipleRepeatedPortChanges() {
        for (int i = 0; i < 2; i++) {
            for (Integer port : ALTERNATIVE_PORTS) {
                destinationPortsContainer.put(port);
            }
        }
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.CHANGES_PORT));
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS));
    }
}
