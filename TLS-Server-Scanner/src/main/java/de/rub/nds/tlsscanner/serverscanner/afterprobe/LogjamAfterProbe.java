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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class LogjamAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable = TestResult.FALSE;
        try {
            if (report.getCipherSuites() != null) {
                for (CipherSuite suite : report.getCipherSuites()) {
                    if (suite.name().contains("DH_anon_EXPORT") || suite.name().contains("DH_DSS_EXPORT")
                        || suite.name().contains("DH_RSA_EXPORT") || suite.name().contains("DHE_DSS_EXPORT")
                        || suite.name().contains("DHE_RSA_EXPORT")) {
                        vulnerable = TestResult.TRUE;
                    }
                }
            } else {
                vulnerable = TestResult.UNCERTAIN;
            }
        } catch (Exception e) {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
