/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.probe.HandshakeSimulationProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.reflections.Reflections;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class ProbeResultTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Before
    public void setUp() {
    }

    /**
     * Test of getFlawString method, of class TestResult.
     */
    @Test
    public void testResultMerge() throws Exception {
        LOGGER.info("Testing result merging:");
        Reflections reflections = new Reflections("de.rub.nds.tlsscanner.serverscanner.probe");
        Set<Class<? extends TlsProbe>> probeClasses = reflections.getSubTypesOf(TlsProbe.class);
        for (Class<? extends TlsProbe> someProbeClass : probeClasses) {
            if (Modifier.isAbstract(someProbeClass.getModifiers())) {
                CONSOLE.info("Skipping:" + someProbeClass.getSimpleName());
                continue;
            }
            String testName = someProbeClass.getSimpleName().replace("Probe", "");
            if (someProbeClass.equals(HandshakeSimulationProbe.class)) {
                LOGGER.info("Skipping: HandshakeSimulation due to performance reasons");
                continue;
            }
            // Trying to find equivalent preparator, message and serializer
            for (Constructor c : someProbeClass.getConstructors()) {
                if (c.getParameterCount() == 2) {
                    if (c.getParameterTypes()[0].equals(ScannerConfig.class)) {
                        LOGGER.info("Testing mergeability:" + testName);
                        TlsProbe probe = (TlsProbe) c.newInstance(null, null);
                        SiteReport report = new SiteReport("somehost");
                        probe.getCouldNotExecuteResult().merge(report);
                        LOGGER.info("--Success");
                        LOGGER.info("Testing printability:");
                        SiteReportPrinter printer = new SiteReportPrinter(report, ScannerDetail.ALL, true);
                        printer.getFullReport();
                        LOGGER.info("--Success");
                    }
                }
            }

        }
        LOGGER.info("Finished result merging test");
    }

}
