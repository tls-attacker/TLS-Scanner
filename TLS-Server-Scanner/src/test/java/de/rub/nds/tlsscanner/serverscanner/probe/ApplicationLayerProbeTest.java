/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag(TestCategories.SLOW_TEST)
public class ApplicationLayerProbeTest {

    private ApplicationLayerProbe probe;
    private ConfigSelector configSelector;
    private ParallelExecutor parallelExecutor;
    private ServerScannerConfig scannerConfig;
    private ServerReport report;

    @BeforeEach
    public void setUp() {
        scannerConfig = mock(ServerScannerConfig.class);
        // No need to mock hostname - handled by probe using clientDelegate

        configSelector = mock(ConfigSelector.class);
        when(configSelector.getScannerConfig()).thenReturn(scannerConfig);

        Config config = Config.createConfig();
        when(configSelector.getAnyWorkingBaseConfig()).thenReturn(config);

        parallelExecutor = mock(ParallelExecutor.class);

        report = new ServerReport("example.com", "example.com", 443);

        probe = new ApplicationLayerProbe(configSelector, parallelExecutor);
    }

    @Test
    public void testProbeRegistersCorrectProperties() {
        // Since we can't easily mock the network interaction,
        // just test that the probe structure is correct

        // Execute without actually running network code
        probe.merge(report);

        // Check that properties exist (even if with default values)
        assertNotNull(report.getResult(TlsAnalyzedProperty.SPEAKS_HTTP));
        assertNotNull(report.getResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS));
    }

    @Test
    public void testMergeWithExistingApplications() {
        // Test that the probe correctly merges with existing applications
        List<ApplicationProtocol> existingApps = new ArrayList<>();
        existingApps.add(ApplicationProtocol.ECHO);
        report.putResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, existingApps);

        // Run merge without actual network test
        probe.merge(report);

        @SuppressWarnings("unchecked")
        List<ApplicationProtocol> mergedApps =
                (List<ApplicationProtocol>)
                        report.getResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS);
        assertNotNull(mergedApps);
        // Should still contain the existing app even without running the test
        assertTrue(mergedApps.contains(ApplicationProtocol.ECHO));
    }
}
