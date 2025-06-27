/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SrpProbeTest {

    private ServerReport report;

    @BeforeEach
    public void setUp() {
        report = new ServerReport();
    }

    @Test
    public void testSrpProbeRegistersCorrectProperties() {
        SrpProbe probe = new SrpProbe(null, null);

        assertEquals(TlsProbeType.SRP, probe.getType());
        assertTrue(
                probe.getAnnouncedResults().contains(TlsAnalyzedProperty.SUPPORTS_SRP_EXTENSION));
        assertTrue(probe.getAnnouncedResults().contains(TlsAnalyzedProperty.SRP_CIPHERSUITES));
        assertTrue(
                probe.getAnnouncedResults()
                        .contains(TlsAnalyzedProperty.MISSING_SRP_EXTENSION_BUG));
    }

    @Test
    public void testMergeDataWithNoSrpSupport() {
        // Create a test probe instance with test data
        SrpProbe probe =
                new SrpProbe(null, null) {
                    @Override
                    protected void mergeData(ServerReport report) {
                        super.mergeData(report);
                    }
                };

        // Merge data with no SRP support
        probe.mergeData(report);

        // Verify the results
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.SUPPORTS_SRP_EXTENSION));
        assertNotNull(report.getResult(TlsAnalyzedProperty.SRP_CIPHERSUITES));
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.MISSING_SRP_EXTENSION_BUG));
    }
}
