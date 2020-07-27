/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

public class EcPublicKeyAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        TestResult reuse;
        try {
            ExtractedValueContainer valueContainer = report.getExtractedValueContainerMap().get(
                    TrackableValueType.ECDHE_PUBKEY);
            if (valueContainer.getNumberOfExtractedValues() >= 2) {
                if (!valueContainer.areAllValuesDiffernt()) {
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
