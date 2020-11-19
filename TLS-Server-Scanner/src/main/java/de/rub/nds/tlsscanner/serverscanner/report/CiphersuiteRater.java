/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.serverscanner.constants.CipherSuiteGrade;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CiphersuiteRater {

    private CiphersuiteRater() {
    }

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
