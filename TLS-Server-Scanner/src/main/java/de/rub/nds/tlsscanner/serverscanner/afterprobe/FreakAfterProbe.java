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
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FreakAfterProbe extends AfterProbe<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    @SuppressWarnings("unchecked")
    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
            TestResult ciphersuiteResult = report.getResultMap().get(TlsAnalyzedProperty.SET_CIPHERSUITES.name());
            if (ciphersuiteResult != null) {
                Set<CipherSuite> ciphersuites = ((SetResult<CipherSuite>) ciphersuiteResult).getSet();
                if (ciphersuites != null) {
                    for (CipherSuite suite : ciphersuites) {
                        if (suite.name().contains("RSA_EXPORT"))
                            vulnerable = TestResults.TRUE;
                    }
                    if (vulnerable != TestResults.TRUE)
                        vulnerable = TestResults.FALSE;
                } else
                    vulnerable = TestResults.UNCERTAIN;
            } else {
                vulnerable = TestResults.ERROR_DURING_TEST;
                LOGGER.debug("property " + TlsAnalyzedProperty.SET_CIPHERSUITES.name()
                    + " requires a TestResult for the FreakAfterProbe but has result null!");
            }
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_FREAK, vulnerable);
    }
}
