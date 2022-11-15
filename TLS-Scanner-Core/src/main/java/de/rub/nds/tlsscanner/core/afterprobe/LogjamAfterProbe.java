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
<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/afterprobe/LogjamAfterProbe.java
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Set;
=======
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
>>>>>>> master:TLS-Scanner-Core/src/main/java/de/rub/nds/tlsscanner/core/afterprobe/LogjamAfterProbe.java

public class LogjamAfterProbe extends AfterProbe<TlsScanReport> {

    @Override
    public void analyze(TlsScanReport report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
<<<<<<< HEAD:TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/afterprobe/LogjamAfterProbe.java
            Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
            if (ciphersuites != null) {
                for (CipherSuite suite : ciphersuites) {
                    if (suite.name().contains("DH_anon_EXPORT") || suite.name().contains("DH_DSS_EXPORT")
                        || suite.name().contains("DH_RSA_EXPORT") || suite.name().contains("DHE_DSS_EXPORT")
                        || suite.name().contains("DHE_RSA_EXPORT")) {
=======
            if (report.getCipherSuites() != null) {
                for (CipherSuite suite : report.getCipherSuites()) {
                    if (suite.name().contains("DH_anon_EXPORT")
                            || suite.name().contains("DH_DSS_EXPORT")
                            || suite.name().contains("DH_RSA_EXPORT")
                            || suite.name().contains("DHE_DSS_EXPORT")
                            || suite.name().contains("DHE_RSA_EXPORT")) {
>>>>>>> master:TLS-Scanner-Core/src/main/java/de/rub/nds/tlsscanner/core/afterprobe/LogjamAfterProbe.java
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
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
