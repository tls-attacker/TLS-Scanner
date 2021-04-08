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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
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
                        for (CipherSuite suite : versionSuitList.getCipherSuiteList()) {
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
