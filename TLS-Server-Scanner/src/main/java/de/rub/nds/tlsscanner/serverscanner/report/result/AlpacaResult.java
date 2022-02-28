/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class AlpacaResult extends ProbeResult {

    private final TestResult strictAlpn;
    private final TestResult strictSni;

    public AlpacaResult(TestResult strictAlpn, TestResult strictSni) {
        super(ProbeType.CROSS_PROTOCOL_ALPACA);
        this.strictSni = strictSni;
        this.strictAlpn = strictAlpn;
    }

    @Override
    protected void mergeData(SiteReport report) {
        if ((strictSni == TestResults.TRUE || strictSni == TestResults.FALSE)
            && (strictAlpn == TestResults.TRUE || strictAlpn == TestResults.FALSE)) {

            TestResult alpacaMitigated;
            if (strictAlpn == TestResults.TRUE && strictSni == TestResults.TRUE) {
                alpacaMitigated = TestResults.TRUE;
            } else if (strictAlpn == TestResults.TRUE || strictSni == TestResults.TRUE) {
                alpacaMitigated = TestResults.PARTIALLY;
            } else {
                alpacaMitigated = TestResults.FALSE;
            }
            report.putResult(AnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(AnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(AnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
        } else {
            report.putResult(AnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(AnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(AnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
        }
    }
}
