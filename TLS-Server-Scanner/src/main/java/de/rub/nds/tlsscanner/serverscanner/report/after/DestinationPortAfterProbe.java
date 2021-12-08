/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DestinationPortAfterProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void analyze(SiteReport report) {
        int intialPort = report.getPort();
        ExtractedValueContainer<Integer> container =
            report.getExtractedValueContainerMap().get(TrackableValueType.DESTINATION_PORT);

        TestResult changesPort;
        try {
            if (container.getNumberOfExtractedValues() >= 1) {
                if (container.getExtractedValueList().get(0) == intialPort) {
                    changesPort = TestResult.FALSE;
                } else {
                    changesPort = TestResult.TRUE;
                }
            } else {
                changesPort = TestResult.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
            changesPort = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.CHANGES_PORT, changesPort);

        TestResult changesPortToRandomPorts;
        try {
            if (container.getNumberOfExtractedValues() >= 2) {
                if (container.areAllValuesIdentical()) {
                    changesPortToRandomPorts = TestResult.FALSE;
                } else {
                    changesPortToRandomPorts = TestResult.TRUE;
                }
            } else {
                changesPortToRandomPorts = TestResult.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
            changesPortToRandomPorts = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS, changesPortToRandomPorts);
    }

}
