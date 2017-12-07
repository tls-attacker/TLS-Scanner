/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Sweet32AfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        if (report.getCipherSuites() != null) {
            for (CipherSuite suite : report.getCipherSuites()) {
                if (suite.name().contains("3DES") || suite.name().contains("IDEA") || suite.name().contains("GOST")) {
                    report.setSweet32Vulnerable(Boolean.TRUE);
                    return;
                }
            }

            report.setSweet32Vulnerable(Boolean.FALSE);
        }
    }
}
