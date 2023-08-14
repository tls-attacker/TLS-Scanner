/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.TlsCoreTestReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class Sweet32AfterProbeTest {

    private TlsCoreTestReport report;
    private Sweet32AfterProbe<TlsCoreTestReport> probe;

    public static Stream<CipherSuite> provideVulnerableCipherSuites() {
        return CipherSuite.getImplemented().stream()
                .filter(cs -> cs.name().contains("3DES") || cs.name().contains("IDEA"));
    }

    public static Stream<CipherSuite> provideSafeCipherSuites() {
        return CipherSuite.getImplemented().stream()
                .filter(cs -> !cs.name().contains("3DES") && !cs.name().contains("IDEA"));
    }

    @BeforeEach
    public void setup() {
        report = new TlsCoreTestReport();
        probe = new Sweet32AfterProbe<>();
    }

    @ParameterizedTest
    @MethodSource("provideVulnerableCipherSuites")
    public void testVulnerableCipherSuites(CipherSuite providedCipherSuite) {
        // test reports that only use vulnerable ciphers
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                Collections.singleton(providedCipherSuite));
        probe.analyze(report);
        assertEquals(
                TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));

        // test reports that use both vulnerable and safe ciphers
        Set<CipherSuite> ciphers = new HashSet<>();
        ciphers.add(providedCipherSuite);
        ciphers.addAll(provideSafeCipherSuites().collect(Collectors.toList()).subList(0, 5));

        // add a number of "random" safe cipher suites to the mix
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, ciphers);
        probe.analyze(report);

        assertEquals(
                TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
    }

    @ParameterizedTest
    @MethodSource("provideSafeCipherSuites")
    public void testSafeCipherSuites(CipherSuite providedCipherSuite) {
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                Collections.singleton(providedCipherSuite));
        probe.analyze(report);
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
    }

    @Test
    public void testNoCipherSuites() {
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, new HashSet<>());
        probe.analyze(report);
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
    }

    /**
     * Test if vulnerability to Sweet32 is uncertain when the ServerReport is empty without host and
     * port.
     */
    @Test
    public void testEmptyServerReport() {
        probe.analyze(report);
        assertEquals(
                TestResults.UNCERTAIN,
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
    }
}
