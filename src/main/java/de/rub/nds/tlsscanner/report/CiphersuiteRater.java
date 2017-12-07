/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;

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
