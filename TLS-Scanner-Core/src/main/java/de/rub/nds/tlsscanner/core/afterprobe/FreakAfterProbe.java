/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/afterprobe/FreakAfterProbe.java
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Set;
=======
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
>>>>>>> master:TLS-Scanner-Core/src/main/java/de/rub/nds/tlsscanner/core/afterprobe/FreakAfterProbe.java

public class FreakAfterProbe extends AfterProbe<TlsScanReport> {

    @Override
    public void analyze(TlsScanReport report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
            Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
            if (ciphersuites != null) {
                for (CipherSuite suite : ciphersuites) {
                    if (suite.name().contains("RSA_EXPORT")) {
                        vulnerable = TestResults.TRUE;
                    }
                }
                if (vulnerable != TestResults.TRUE) {
                    vulnerable = TestResults.FALSE;
                }
            } else {
                vulnerable = TestResults.UNCERTAIN;
            }
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK, vulnerable);
    }
}
