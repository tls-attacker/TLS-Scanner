/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Set;

/**
 * AfterProbe implementation that checks for vulnerability to the SWEET32 attack by detecting
 * support for 64-bit block cipher suites (3DES and IDEA).
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public class Sweet32AfterProbe<ReportT extends TlsScanReport> extends AfterProbe<ReportT> {

    /**
     * Analyzes the supported cipher suites to determine if the server is vulnerable to the SWEET32
     * attack. A server is vulnerable if it supports cipher suites using 64-bit block ciphers like
     * 3DES or IDEA. Sets the result to TRUE if vulnerable, FALSE if not vulnerable, UNCERTAIN if
     * cipher suites cannot be determined, or ERROR_DURING_TEST if an exception occurs.
     *
     * @param report the TLS scan report containing supported cipher suite information
     */
    @Override
    public void analyze(ReportT report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
            Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
            if (ciphersuites != null) {
                for (CipherSuite suite : ciphersuites) {
                    if (suite.name().contains("3DES") || suite.name().contains("IDEA")) {
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
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32, vulnerable);
    }
}
