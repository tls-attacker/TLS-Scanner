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
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PoodleAfterProbe extends AfterProbe<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
            TestResult ssl3Result = report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3);
            if (ssl3Result == TestResults.TRUE) {
                List<VersionSuiteListPair> versionsuiteList = report.getVersionSuitePairs();
                if (versionsuiteList != null) {
                    for (VersionSuiteListPair versionSuitList : versionsuiteList) {
                        if (versionSuitList.getVersion() == ProtocolVersion.SSL3) {
                            for (CipherSuite suite : versionSuitList.getCipherSuiteList()) {
                                if (suite.isCBC()) {
                                    report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.TRUE);
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    vulnerable = TestResults.ERROR_DURING_TEST;
                    LOGGER.debug("property " + TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS.name()
                        + " requires a TestResult for the PoodleAfterProbe but has result null!");
                }
            }
            report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, Boolean.FALSE);
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_POODLE, vulnerable);
    }
}
