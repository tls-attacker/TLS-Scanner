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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class FreakAfterProbeTest {

    private TlsCoreTestReport report;
    private FreakAfterProbe<TlsCoreTestReport> probe;

    public static Stream<CipherSuite> provideVulnerableCipherSuites() {
        return CipherSuite.getImplemented().stream().filter(cs -> cs.name().contains("RSA_EXPORT"));
    }

    public static Stream<CipherSuite> provideSafeCipherSuites() {
        return CipherSuite.getImplemented().stream()
                .filter(cs -> !cs.name().contains("RSA_EXPORT"));
    }

    @BeforeEach
    public void setup() {
        report = new TlsCoreTestReport();
        probe = new FreakAfterProbe<>();
    }

    @ParameterizedTest
    @MethodSource("provideVulnerableCipherSuites")
    public void testVulnerableCipherSuites(CipherSuite providedCipherSuite) {
        // test reports that only use vulnerable ciphers
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                Collections.singleton(providedCipherSuite));
        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK));

        // test reports that use both vulnerable and safe ciphers
        HashSet<CipherSuite> ciphers = new HashSet<>();

        ciphers.add(providedCipherSuite);
        ciphers.addAll(provideSafeCipherSuites().collect(Collectors.toList()).subList(0, 5));
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, ciphers);
        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK));
    }

    @ParameterizedTest
    @MethodSource("provideSafeCipherSuites")
    public void testSafeCipherSuites(CipherSuite providedCipherSuite) {
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                Collections.singleton(providedCipherSuite));
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK));
    }

    @Test
    public void testNoCipherSuites() {
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, new HashSet<>());
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK));
    }

    @Test
    public void testEmptyServerReport() {
        TlsCoreTestReport emptyReport = new TlsCoreTestReport();
        probe.analyze(emptyReport);
        assertEquals(
                TestResults.UNCERTAIN,
                emptyReport.getResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK));
    }
}
