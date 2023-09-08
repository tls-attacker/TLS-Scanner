/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

public class EcPublicKeyAfterProbe<ReportT extends TlsScanReport> extends AfterProbe<ReportT> {

    @Override
    public void analyze(ReportT report) {
        TestResult reuse;
        try {
            ExtractedValueContainer<?> valueContainer =
                    report.getExtractedValueContainerMap().get(TrackableValueType.ECDHE_PUBKEY);
            if (valueContainer.getNumberOfExtractedValues() >= 2) {
                if (!valueContainer.areAllValuesDifferent()) {
                    reuse = TestResults.TRUE;
                } else {
                    reuse = TestResults.FALSE;
                }
            } else {
                reuse = TestResults.COULD_NOT_TEST;
            }
        } catch (Exception e) {
            reuse = TestResults.ERROR_DURING_TEST;
        }

        report.putResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY, reuse);
    }
}
