/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class EcPublicKeyAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
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

        report.putResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY, reuse);
    }

}
