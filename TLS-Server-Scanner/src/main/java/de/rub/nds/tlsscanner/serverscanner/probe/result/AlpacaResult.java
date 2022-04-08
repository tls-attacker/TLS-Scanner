/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class AlpacaResult extends ProbeResult<ServerReport> {

    private final TestResult strictAlpn;
    private final TestResult strictSni;

    public AlpacaResult(TestResult strictAlpn, TestResult strictSni) {
        super(TlsProbeType.CROSS_PROTOCOL_ALPACA);
        this.strictSni = strictSni;
        this.strictAlpn = strictAlpn;
    }

    @Override
    protected void mergeData(ServerReport report) {
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
            report.putResult(TlsAnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(TlsAnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
        } else {
            report.putResult(TlsAnalyzedProperty.STRICT_SNI, strictSni);
            report.putResult(TlsAnalyzedProperty.STRICT_ALPN, strictAlpn);
            report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
        }
    }
}
