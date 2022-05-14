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

public class Sweet32AfterProbe extends AfterProbe<ServerReport> {

    @Override
    public void analyze(ServerReport report) {
        TestResult vulnerable = TestResults.FALSE;
        try {
        	TestResult ciphersuiteResult = report.getResultMap().get(TlsAnalyzedProperty.SET_CIPHERSUITES.name());
        	if (ciphersuiteResult != null) {
        		@SuppressWarnings("unchecked")
				Set<CipherSuite> ciphersuites = ((SetResult<CipherSuite>) ciphersuiteResult).getSet();
	            if (ciphersuites != null) {
	                for (CipherSuite suite : ciphersuites) {
	                    if (suite.name().contains("3DES") || suite.name().contains("IDEA")) {
	                        vulnerable = TestResults.TRUE;
	                    }
	                }
	            } else {
	                vulnerable = TestResults.UNCERTAIN;
	            }
        	}
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32, vulnerable);
    }
}
