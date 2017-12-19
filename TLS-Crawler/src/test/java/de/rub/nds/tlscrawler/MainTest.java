/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.utility.Tuple;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the Main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MainTest {

    @Test
    public void setUpScansSmokeTest() {
        List<IScan> scans = Main.setUpScans();

        for (IScan scan : scans) {
            assertNotNull(scan);
        }

        List<String> scanNames = scans.stream().map(x -> x.getName()).collect(Collectors.toList());

        for (int i = 0; i < scanNames.size(); i++) {
            for (int j = 0; j < scanNames.size(); j++) {
                if (i != j) {
                    assertNotEquals(scanNames.get(i), scanNames.get(j));
                }
            }
        }

        assertTrue(scanNames.contains("null_scan"));
        assertTrue(scanNames.contains("test_scan"));
        assertTrue(scanNames.contains("ping_scan"));
        assertTrue(scanNames.contains("tls_scan"));
    }

    @Test
    public void setUpProvidersSmokeTest() {
        StartupOptions options = mock(StartupOptions.class);
        options.testMode = true;

        Tuple<IOrchestrationProvider, IPersistenceProvider> providers = Main.setUpProviders(options);

        assertNotNull(providers);
        assertNotNull(providers.getFirst());
        assertNotNull(providers.getSecond());
    }
}