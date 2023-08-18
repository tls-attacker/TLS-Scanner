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

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class PoodleAfterProbeTest {

    private ServerReport report;
    private PoodleAfterProbe probe;

    public static Stream<CipherSuite> provideVulnerableCipherSuites() {
        return CipherSuite.getImplemented().stream().filter(cs -> cs.isCBC());
    }

    public static Stream<CipherSuite> provideSafeCipherSuites() {
        return CipherSuite.getImplemented().stream().filter(cs -> !cs.isCBC());
    }

    @BeforeEach
    public void setup() {
        report = new ServerReport();
        probe = new PoodleAfterProbe();
    }

    @ParameterizedTest
    @MethodSource("provideVulnerableCipherSuites")
    public void testVulnerableCipherSuitesWithoutSSL3(CipherSuite providedCipherSuite) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.FALSE);
        VersionSuiteListPair versionSuiteListPair =
                new VersionSuiteListPair(ProtocolVersion.TLS12, List.of(providedCipherSuite));
        report.putResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, List.of(versionSuiteListPair));
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }

    @ParameterizedTest
    @MethodSource("provideVulnerableCipherSuites")
    public void testVulnerableCipherSuitesWithSSL3(CipherSuite providedCipherSuite) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
        VersionSuiteListPair versionSuiteListPair =
                new VersionSuiteListPair(ProtocolVersion.SSL3, List.of(providedCipherSuite));
        report.putResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, List.of(versionSuiteListPair));
        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }

    @ParameterizedTest
    @MethodSource("provideVulnerableCipherSuites")
    public void testMixedCipherSuites(CipherSuite providedCipherSuite) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);

        VersionSuiteListPair vulnerableVersionSuiteListPair =
                new VersionSuiteListPair(ProtocolVersion.SSL3, List.of(providedCipherSuite));
        VersionSuiteListPair safeVersionSuiteListPair =
                new VersionSuiteListPair(
                        ProtocolVersion.TLS12, List.of(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                List.of(vulnerableVersionSuiteListPair, safeVersionSuiteListPair));

        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));

        vulnerableVersionSuiteListPair =
                new VersionSuiteListPair(ProtocolVersion.TLS12, List.of(providedCipherSuite));
        safeVersionSuiteListPair =
                new VersionSuiteListPair(
                        ProtocolVersion.SSL3, List.of(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        report.putResult(
                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                List.of(vulnerableVersionSuiteListPair, safeVersionSuiteListPair));
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }

    @ParameterizedTest
    @MethodSource("provideSafeCipherSuites")
    public void testSafeCipherSuites(CipherSuite providedCipherSuite) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
        VersionSuiteListPair versionSuiteListPair =
                new VersionSuiteListPair(ProtocolVersion.SSL3, List.of(providedCipherSuite));
        report.putResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, List.of(versionSuiteListPair));
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }

    @Test
    public void testNoCipherSuites() {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);

        probe.analyze(report);
        assertEquals(
                TestResults.ERROR_DURING_TEST,
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
        report.putResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, new LinkedList<>());
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }

    @Test
    public void testEmptyServerReport() {
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE));
    }
}
