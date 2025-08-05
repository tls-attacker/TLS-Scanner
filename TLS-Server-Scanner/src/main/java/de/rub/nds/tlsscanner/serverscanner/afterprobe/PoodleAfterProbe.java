/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class PoodleAfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable;
        try {
            TestResult ssl3Result = report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3);
            if (ssl3Result == TestResults.TRUE) {
                for (VersionSuiteListPair versionSuitList : report.getVersionSuitePairs()) {
                    if (versionSuitList.getVersion() == ProtocolVersion.SSL3) {
                        for (CipherSuite suite : versionSuitList.getCipherSuiteList()) {
                            if (suite.isCBC()) {
                                report.putResult(
                                        TlsAnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.TRUE);
                                return;
                            }
                        }
                    }
                }
            }
            vulnerable = TestResults.FALSE;
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, vulnerable);
    }
}
