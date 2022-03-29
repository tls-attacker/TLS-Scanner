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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class PoodleAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable = TestResult.NOT_TESTED_YET;
        try {
            TestResult ssl3Result = report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3);
            if (ssl3Result == TestResult.TRUE) {
                for (VersionSuiteListPair versionSuitList : report.getVersionSuitePairs()) {
                    if (versionSuitList.getVersion() == ProtocolVersion.SSL3) {
                        for (CipherSuite suite : versionSuitList.getCipherSuiteList()) {
                            if (suite.isCBC()) {
                                report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.TRUE);
                                return;
                            }
                        }
                    }
                }
            }
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.FALSE);
        } catch (Exception e) {
            vulnerable = TestResult.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, vulnerable);
    }
}
