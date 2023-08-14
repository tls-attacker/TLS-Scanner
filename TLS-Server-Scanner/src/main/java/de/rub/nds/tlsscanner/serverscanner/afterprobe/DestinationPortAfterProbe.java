/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DestinationPortAfterProbe extends AfterProbe<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void analyze(ServerReport report) {
        int intialPort = report.getPort();
        ExtractedValueContainer<Integer> container =
                report.getExtractedValueContainer(
                        TrackableValueType.DESTINATION_PORT, Integer.class);

        TestResult changesPort;
        try {
            if (container.getNumberOfExtractedValues() >= 1) {
                if (container.getExtractedValueList().get(0) == intialPort) {
                    changesPort = TestResults.FALSE;
                } else {
                    changesPort = TestResults.TRUE;
                }
            } else {
                changesPort = TestResults.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
            changesPort = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.CHANGES_PORT, changesPort);

        TestResult changesPortToRandomPorts;
        try {
            if (container.getNumberOfExtractedValues() >= 2) {
                if (container.areAllValuesIdentical()) {
                    changesPortToRandomPorts = TestResults.FALSE;
                } else {
                    changesPortToRandomPorts = TestResults.TRUE;
                }
            } else {
                changesPortToRandomPorts = TestResults.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
            changesPortToRandomPorts = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(
                TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS, changesPortToRandomPorts);
    }
}
