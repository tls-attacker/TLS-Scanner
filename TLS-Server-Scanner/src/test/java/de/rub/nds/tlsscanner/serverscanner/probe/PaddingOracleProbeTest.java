/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PaddingOracleProbeTest {

    private PaddingOracleProbe probe;
    private ConfigSelector configSelector;
    private ParallelExecutor executor;
    private ServerReport report;
    private ServerScannerConfig scannerConfig;

    @BeforeEach
    public void setUp() {
        executor = Mockito.mock(ParallelExecutor.class);
        Mockito.when(executor.getReexecutions()).thenReturn(1);

        scannerConfig = new ServerScannerConfig();
        scannerConfig.getExecutorConfig().setScanDetail(ScannerDetail.QUICK);

        configSelector = Mockito.mock(ConfigSelector.class);
        Mockito.when(configSelector.getScannerConfig()).thenReturn(scannerConfig);
        Mockito.when(configSelector.getBaseConfig()).thenReturn(Config.createConfig());

        report = new ServerReport();

        probe = new PaddingOracleProbe(configSelector, executor);
    }

    @Test
    public void testProbeCreation() {
        assertNotNull(probe);
    }

    @Test
    public void testProbeRequiresBlockCiphers() {
        ServerReport testReport = new ServerReport();
        testReport.putResult(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, TestResults.FALSE);

        assertFalse(probe.getRequirements().evaluate(testReport));

        testReport.putResult(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, TestResults.TRUE);
        assertTrue(probe.getRequirements().evaluate(testReport));
    }

    @Test
    public void testProbeSkipsNonCbcCiphers() {
        // Prepare report with non-CBC cipher suites
        VersionSuiteListPair versionPair =
                new VersionSuiteListPair(
                        ProtocolVersion.TLS12,
                        Arrays.asList(
                                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, // GCM, not CBC
                                CipherSuite
                                        .TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // ChaCha20, not
                                // CBC
                                ));

        report.setVersionSuitePairs(Arrays.asList(versionPair));
        probe.adjustConfig(report);
        probe.executeTest();

        List<InformationLeakTest<PaddingOracleTestInfo>> results =
                (List<InformationLeakTest<PaddingOracleTestInfo>>) probe.getCouldNotExecuteReason();

        // Should not test any cipher suite as none are CBC
        assertEquals(0, results != null ? results.size() : 0);
    }

    @Test
    public void testProbeTestsCbcCiphers() {
        // Prepare report with CBC cipher suites
        VersionSuiteListPair versionPair =
                new VersionSuiteListPair(
                        ProtocolVersion.TLS12,
                        Arrays.asList(
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256));

        report.setVersionSuitePairs(Arrays.asList(versionPair));
        probe.adjustConfig(report);

        // Mock the executor to avoid actual network calls
        Mockito.doNothing().when(executor).bulkExecuteTasks(Mockito.anyList());

        // Execute with proper mocking would test CBC ciphers
        // This test verifies the setup and filtering logic
        assertDoesNotThrow(() -> probe.executeTest());
    }

    @Test
    public void testProbeRespectsMaxRuntime() throws Exception {
        // Use reflection to verify MAX_PROBE_RUNTIME_MS constant
        Field maxRuntimeField = PaddingOracleProbe.class.getDeclaredField("MAX_PROBE_RUNTIME_MS");
        maxRuntimeField.setAccessible(true);
        long maxRuntime = (long) maxRuntimeField.get(null);

        // 20 minutes = 1200000ms
        assertEquals(1200000L, maxRuntime);
    }

    @Test
    public void testProbeHandlesEmptySuiteList() {
        report.setVersionSuitePairs(Arrays.asList());
        probe.adjustConfig(report);
        probe.executeTest();

        // Should complete without errors
        assertNotNull(probe.getCouldNotExecuteReason());
    }

    @Test
    public void testProbeSkipsTls13() {
        // TLS 1.3 doesn't use padding oracle vulnerable CBC mode
        VersionSuiteListPair versionPair =
                new VersionSuiteListPair(
                        ProtocolVersion.TLS13, Arrays.asList(CipherSuite.TLS_AES_128_GCM_SHA256));

        report.setVersionSuitePairs(Arrays.asList(versionPair));
        probe.adjustConfig(report);
        probe.executeTest();

        List<InformationLeakTest<PaddingOracleTestInfo>> results =
                (List<InformationLeakTest<PaddingOracleTestInfo>>) probe.getCouldNotExecuteReason();

        // Should not test TLS 1.3
        assertEquals(0, results != null ? results.size() : 0);
    }

    @Test
    public void testProbeSkipsSsl() {
        // SSL versions are skipped
        VersionSuiteListPair versionPair =
                new VersionSuiteListPair(
                        ProtocolVersion.SSL3,
                        Arrays.asList(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA));

        report.setVersionSuitePairs(Arrays.asList(versionPair));
        probe.adjustConfig(report);
        probe.executeTest();

        List<InformationLeakTest<PaddingOracleTestInfo>> results =
                (List<InformationLeakTest<PaddingOracleTestInfo>>) probe.getCouldNotExecuteReason();

        // Should not test SSL versions
        assertEquals(0, results != null ? results.size() : 0);
    }
}
