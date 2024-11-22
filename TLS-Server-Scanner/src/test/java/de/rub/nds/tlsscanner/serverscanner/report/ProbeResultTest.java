/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.report.DefaultPrintingScheme;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

public class ProbeResultTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Test of getFlawString method, of class TestResults. */
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
            // Trying to find equivalent preparator, message and serializer
            for (Constructor c : someProbeClass.getConstructors()) {
                if (c.getParameterCount() == 2) {
                    if (c.getParameterTypes()[0].equals(ServerScannerConfig.class)) {
                        LOGGER.info("Testing mergeability:" + testName);
                        TlsProbe probe =
                                (TlsProbe)
                                        c.newInstance(
                                                new ServerScannerConfig(new GeneralDelegate()),
                                                new ParallelExecutor(1, 1));
                        ServerReport report = new ServerReport("somehost", 443);
                        probe.merge(report);
                        LOGGER.info("--Success");
                        LOGGER.info("Testing printability:");
                        ServerReportPrinter printer =
                                new ServerReportPrinter(
                                        report,
                                        ScannerDetail.ALL,
                                        DefaultPrintingScheme.getDefaultPrintingScheme(),
                                        true);
                        printer.getFullReport();
                        LOGGER.info("--Success");
                    }
                }
            }
        }
        LOGGER.info("Finished result merging test");
    }
}
