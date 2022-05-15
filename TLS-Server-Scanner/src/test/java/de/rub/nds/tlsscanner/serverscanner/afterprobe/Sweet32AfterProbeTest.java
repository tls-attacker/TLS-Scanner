/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.Assert.assertEquals;

import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class Sweet32AfterProbeTest {

    private ServerReport report;
    private static List<CipherSuite> vulnerableCipherSuites;
    private static List<CipherSuite> safeCipherSuites;
    private Sweet32AfterProbe probe;

    @BeforeClass
    public static void filterVulnerableCipherSuites() {
        vulnerableCipherSuites = new LinkedList<>();
        safeCipherSuites = new LinkedList<>();

        for (CipherSuite c : CipherSuite.getImplemented()) {
            if (c.name().contains("3DES") || c.name().contains("IDEA")) {
                vulnerableCipherSuites.add(c);
            } else {
                safeCipherSuites.add(c);
            }
        }
        Collections.shuffle(safeCipherSuites, new Random(2147483647));
    }

    @Before
    public void setup() {
        report = new ServerReport("sweet32afterprobetest", 443);
        probe = new Sweet32AfterProbe();
    }

    /**
     * Test if probe recognizes use of cipher suites using a 64 bit block size cipher.
     */
    @Test
    public void testVulnerableCipherSuites() {
        // test reports that only use vulnerable ciphers
        for (CipherSuite vulnerable : vulnerableCipherSuites) {
            report.putResult(TlsAnalyzedProperty.SET_CIPHERSUITES,
                new SetResult<>(Collections.singleton(vulnerable), "CIPHERSUITES"));
            probe.analyze(report);
            assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
        }

        // test reports that use both vulnerable and safe ciphers
        for (CipherSuite vulnerable : vulnerableCipherSuites) {
            Set<CipherSuite> ciphers = new HashSet<>();
            ciphers.add(vulnerable);
            // add a number of "random" safe cipher suites to the mix
            ciphers.addAll(safeCipherSuites.subList(0, 10));

            report.putResult(TlsAnalyzedProperty.SET_CIPHERSUITES, new SetResult<>(ciphers, "CIPHERSUITES"));
            probe.analyze(report);
            assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
        }
    }

    /**
     * Test if probe correctly identifies cipher suites not using 64 bit blocksize ciphers as safe
     */
    @Test
    public void testSafeCipherSuites() {
        for (CipherSuite safe : safeCipherSuites) {
            report.putResult(TlsAnalyzedProperty.SET_CIPHERSUITES,
                new SetResult<>(Collections.singleton(safe), "CIPHERSUITES"));
            probe.analyze(report);
            assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
        }
    }

    /**
     * Test if probe recognizes ServerReport without any ciphers as invulnerable to Sweet32.
     */
//    @Test
//    public void testNoCipherSuites() {
//        probe.analyze(report);
//        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
//    }

    /**
     * Test if vulnerability to Sweet32 is uncertain when the ServerReport is empty without host and port.
     */
    @Test
    public void testEmptyServerReport() {
        ServerReport emptyReport = new ServerReport();
        probe.analyze(emptyReport);
        assertEquals(TestResults.UNCERTAIN, emptyReport.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32));
    }

}
