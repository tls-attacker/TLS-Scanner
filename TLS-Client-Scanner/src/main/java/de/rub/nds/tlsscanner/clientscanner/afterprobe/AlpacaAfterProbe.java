/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

public class AlpacaAfterProbe extends AfterProbe<ClientReport> {

    @Override
    public void analyze(ClientReport report) {
        final TestResult strictSni = report.getResult(TlsAnalyzedProperty.STRICT_SNI);
        final TestResult strictAlpn = report.getResult(TlsAnalyzedProperty.STRICT_ALPN);

        if ((strictSni != TestResults.TRUE && strictSni != TestResults.FALSE)
                || (strictAlpn != TestResults.TRUE && strictAlpn != TestResults.FALSE)) {
            // at least one of the two properties could not be evaluated
            report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
            return;
        }

        if (strictAlpn == TestResults.TRUE && strictSni == TestResults.TRUE) {
            report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.TRUE);
            return;
        }

        if (strictAlpn == TestResults.TRUE || strictSni == TestResults.TRUE) {
            report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.PARTIALLY);
            return;
        }

        report.putResult(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.FALSE);
    }
}
