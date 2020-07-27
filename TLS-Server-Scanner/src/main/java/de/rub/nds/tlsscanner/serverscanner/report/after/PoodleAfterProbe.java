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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PoodleAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        TestResult vulnerable = TestResult.NOT_TESTED_YET;
        try {
            TestResult ssl3Result = report.getResult(AnalyzedProperty.SUPPORTS_SSL_3);
            if (ssl3Result == TestResult.TRUE) {
                for (VersionSuiteListPair versionSuitList : report.getVersionSuitePairs()) {
                    if (versionSuitList.getVersion() == ProtocolVersion.SSL3) {
                        for (CipherSuite suite : versionSuitList.getCiphersuiteList()) {
                            if (suite.isCBC()) {
                                report.putResult(AnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.TRUE);
                                return;
                            }
                        }
                    }
                }
                report.putResult(AnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.FALSE);
            } else {
                report.putResult(AnalyzedProperty.VULNERABLE_TO_POODLE, ssl3Result);
            }
        } catch (Exception e) {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(AnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
