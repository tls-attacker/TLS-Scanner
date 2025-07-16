/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;

public class CipherSuiteRater {

    private CipherSuiteRater() {}

    /**
     * Evaluates the security grade of a given cipher suite.
     *
     * @param suite The cipher suite to evaluate
     * @return The security grade of the cipher suite (LOW, MEDIUM, GOOD, or NONE)
     */
    public static CipherSuiteGrade getGrade(CipherSuite suite) {
        if (suite.name().contains("anon")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("EXPORT")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("NULL")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("RC2")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("RC4")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("IDEA")) {
            return CipherSuiteGrade.MEDIUM;
        }
        if (suite.name().contains("3DES")) {
            return CipherSuiteGrade.MEDIUM;
        }
        if (suite.name().contains("DES")) {
            return CipherSuiteGrade.LOW;
        }
        if (suite.name().contains("CHACHA20_POLY1305")) {
            return CipherSuiteGrade.GOOD;
        }
        if (suite.name().contains("GCM")) {
            return CipherSuiteGrade.GOOD;
        }
        if (suite.name().contains("CCM")) {
            return CipherSuiteGrade.GOOD;
        }
        if (suite.name().contains("OCB")) {
            return CipherSuiteGrade.GOOD;
        }
        if (suite.name().toLowerCase().contains("fortezza")) {
            return CipherSuiteGrade.MEDIUM;
        }
        return CipherSuiteGrade.NONE;
    }
}
