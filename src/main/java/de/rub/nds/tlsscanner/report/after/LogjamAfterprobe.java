/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class LogjamAfterprobe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        TestResult vulnerable = TestResult.UNTESTED;
        try {
            if (report.getCipherSuites() != null) {
                for (CipherSuite suite : report.getCipherSuites()) {
                    if (suite.name().contains("DH_anon_EXPORT") || suite.name().contains("DH_DSS_EXPORT") || suite.name().contains("DH_RSA_EXPORT") || suite.name().contains("DHE_DSS_EXPORT") || suite.name().contains("DHE_RSA_EXPORT")) {
                        vulnerable = TestResult.TRUE;
                    }
                }
                vulnerable = TestResult.FALSE;
            } else {
                vulnerable = TestResult.UNCERTAIN;
            }
        } catch(Exception e) {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
