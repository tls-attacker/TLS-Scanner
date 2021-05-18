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

public class EcPublicKeyAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        TestResult reuse;
        try {
            ExtractedValueContainer valueContainer =
                report.getExtractedValueContainerMap().get(TrackableValueType.ECDHE_PUBKEY);
            if (valueContainer.getNumberOfExtractedValues() >= 2) {
                if (!valueContainer.areAllValuesDifferent()) {
                    reuse = TestResult.TRUE;
                } else {
                    reuse = TestResult.FALSE;
                }
            } else {
                reuse = TestResult.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            reuse = TestResult.ERROR_DURING_TEST;
        }

        report.putResult(AnalyzedProperty.REUSES_EC_PUBLICKEY, reuse);
    }

}
