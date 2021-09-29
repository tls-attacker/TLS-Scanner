/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
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
        TestResult changesPortTestResult;

        try {
            ExtractedValueContainer<HandshakeMessageType> container =
                report.getExtractedValueContainerMap().get(TrackableValueType.DESTINATION_PORT);
            if (container.getNumberOfExtractedValues() >= 2) {
                if (container.areAllValuesDifferent()) {
                    changesPortTestResult = TestResult.TRUE;
                } else {
                    changesPortTestResult = TestResult.FALSE;
                }
            } else {
                changesPortTestResult = TestResult.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            LOGGER.error(e.toString());
            changesPortTestResult = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.CHANGES_PORT, changesPortTestResult);
    }

}
