/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author ic0ns
 */
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
        if ((strictSni == TestResult.TRUE || strictSni == TestResult.FALSE)
            && (strictAlpn == TestResult.TRUE || strictAlpn == TestResult.FALSE)) {

            TestResult alpacaMitigated;
            if (strictAlpn == TestResult.TRUE && strictSni == TestResult.TRUE) {
                alpacaMitigated = TestResult.TRUE;
            } else if (strictAlpn == TestResult.TRUE || strictSni == TestResult.TRUE) {
                alpacaMitigated = TestResult.PARTIALLY;
            } else {
                alpacaMitigated = TestResult.FALSE;
            }
            report.putResult(AnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(AnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(AnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
        } else {
            report.putResult(AnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(AnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(AnalyzedProperty.ALPACA_MITIGATED, TestResult.UNCERTAIN);
        }
    }
}
