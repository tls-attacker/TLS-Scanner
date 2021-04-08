/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class LogjamAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        TestResult vulnerable = TestResult.NOT_TESTED_YET;
        try {
            if (report.getCipherSuites() != null) {
                for (CipherSuite suite : report.getCipherSuites()) {
                    if (suite.name().contains("DH_anon_EXPORT") || suite.name().contains("DH_DSS_EXPORT")
                        || suite.name().contains("DH_RSA_EXPORT") || suite.name().contains("DHE_DSS_EXPORT")
                        || suite.name().contains("DHE_RSA_EXPORT")) {
                        vulnerable = TestResult.TRUE;
                    }
                }
                vulnerable = TestResult.FALSE;
            } else {
                vulnerable = TestResult.UNCERTAIN;
            }
        } catch (Exception e) {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
