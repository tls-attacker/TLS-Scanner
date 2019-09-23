/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.LinkedList;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.reflections.Reflections;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
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
        LOGGER.info("Testint result merging:");
        Reflections reflections = new Reflections("de.rub.nds.tlsscanner.probe");
        Set<Class<? extends TlsProbe>> resultClasses = reflections.getSubTypesOf(TlsProbe.class);
        for (Class<? extends TlsProbe> someResultClass : resultClasses) {
            if (Modifier.isAbstract(someResultClass.getModifiers())) {
                CONSOLE.info("Skipping:" + someResultClass.getSimpleName());
                continue;
            }
            String testName = someResultClass.getSimpleName().replace("Result", "");

            // Trying to find equivalent preparator, message and serializer
            for (Constructor c : someResultClass.getConstructors()) {
                if (c.getParameterCount() == 2) {
                    if (c.getParameterTypes()[0].equals(ScannerConfig.class)) {
                        System.out.println("Testing:" + testName);
                        TlsProbe probe = (TlsProbe) c.newInstance(null, null);
                        SiteReport report = new SiteReport("somehost", new LinkedList<>(), true);
                        probe.getCouldNotExecuteResult().merge(report);
                        System.out.println("--Success");
                    }
                }
            }

        }
        LOGGER.info("Finished result merging test");
    }

}
