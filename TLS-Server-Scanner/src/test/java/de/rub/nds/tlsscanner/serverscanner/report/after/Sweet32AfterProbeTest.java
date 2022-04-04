/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class Sweet32AfterProbeTest {

    private SiteReport report;
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
        Collections.shuffle(safeCipherSuites);
    }

    @Before
    public void setup() {
        report = new SiteReport("sweet32afterprobetest", 443);
        probe = new Sweet32AfterProbe();
    }

    /**
     * Test if probe recognizes use of cipher suites using a 64 bit block size cipher.
     */
    @Test
    public void testVulnerableCipherSuites() {
        // test reports that only use vulnerable ciphers
        for (CipherSuite vulnerable : vulnerableCipherSuites) {
            report.setCipherSuites(Collections.singleton(vulnerable));
            probe.analyze(report);
            assertEquals(report.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32), TestResult.TRUE);
        }

        // test reports that use both vulnerable and safe ciphers
        for (CipherSuite vulnerable : vulnerableCipherSuites) {
            Set<CipherSuite> ciphers = new HashSet<>();
            ciphers.add(vulnerable);
            ciphers.addAll(safeCipherSuites.subList(0, 5));

            report.setCipherSuites(ciphers);
            probe.analyze(report);
            assertEquals(report.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32), TestResult.TRUE);
        }
    }

    /**
     * Test if probe correctly identifies cipher suites not using 64 bit blocksize ciphers as safe
     */
    @Test
    public void testSafeCipherSuites() {
        for (CipherSuite safe : safeCipherSuites) {
            report.setCipherSuites(Collections.singleton(safe));
            probe.analyze(report);
            assertEquals(report.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32), TestResult.FALSE);
        }
    }

    /**
     * Test if probe recognizes SiteReport without any ciphers as invulnerable to Sweet32.
     */
    @Test
    public void testNoCipherSuites() {
        probe.analyze(report);
        assertEquals(report.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32), TestResult.FALSE);
    }

    /**
     * Test if vulnerability to Sweet32 is uncertain when the SiteReport is empty without host and port.
     */
    @Test
    public void testEmptySiteReport() {
        SiteReport emptyReport = new SiteReport();
        probe.analyze(emptyReport);
        assertEquals(emptyReport.getResult(AnalyzedProperty.VULNERABLE_TO_SWEET_32), TestResult.UNCERTAIN);
    }

}
